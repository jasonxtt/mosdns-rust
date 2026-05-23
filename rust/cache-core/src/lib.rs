use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::RData;
use ipnet::IpNet;
use prost::Message as ProstMessage;
use std::collections::{HashMap, VecDeque};
use std::io::{Cursor, Read, Write};
use std::net::IpAddr;
use std::os::raw::{c_int, c_longlong, c_uchar, c_ulonglong};
use std::slice;
use std::time::{Duration, SystemTime};

const RUNTIME_VERSION: &[u8] = b"mosdns-cache-core/0.1.0\0";
const EXPIRED_MSG_TTL: u32 = 5;
const MIN_CACHEABLE_TTL: u32 = 5;
const EMPTY_ANSWER_MAX_TTL: u32 = 300;
const DUMP_HEADER: &str = "mosdns_cache_v2";
const DUMP_BLOCK_SIZE: usize = 128;
const DUMP_MAXIMUM_BLOCK_LENGTH: usize = 1 << 20;

#[derive(Clone, PartialEq, ProstMessage)]
struct CachedEntryPb {
    #[prost(bytes, tag = "1")]
    key: Vec<u8>,
    #[prost(bytes, tag = "2")]
    msg: Vec<u8>,
    #[prost(int64, tag = "3")]
    cache_expiration_time: i64,
    #[prost(int64, tag = "4")]
    msg_expiration_time: i64,
    #[prost(int64, tag = "5")]
    msg_stored_time: i64,
    #[prost(string, tag = "6")]
    domain_set: String,
}

#[derive(Clone, PartialEq, ProstMessage)]
struct CacheDumpBlockPb {
    #[prost(message, repeated, tag = "1")]
    entries: Vec<CachedEntryPb>,
}

#[repr(C)]
pub struct MosdnsCacheLookupResult {
    status: c_int,
    state: c_int,
    response_ptr: *mut c_uchar,
    response_len: c_ulonglong,
    domain_set_ptr: *mut c_uchar,
    domain_set_len: c_ulonglong,
}

#[repr(C)]
pub struct MosdnsCacheBytesResult {
    status: c_int,
    ptr: *mut c_uchar,
    len: c_ulonglong,
}

#[derive(Clone, Debug)]
pub struct CacheConfig {
    pub size: usize,
    pub lazy_cache_ttl: u32,
    pub enable_ecs: bool,
    pub exclude_ips: Vec<IpNet>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LookupState {
    Miss,
    FreshHit,
    LazyHit,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LookupResult {
    pub state: LookupState,
    pub response: Option<Vec<u8>>,
    pub domain_set: Option<String>,
}

#[derive(Clone, Debug)]
struct CacheEntry {
    response: Vec<u8>,
    stored_at: SystemTime,
    msg_expires_at: SystemTime,
    cache_expires_at: SystemTime,
    domain_set: Option<String>,
}

#[derive(Debug)]
pub struct CacheCore {
    config: CacheConfig,
    entries: HashMap<Vec<u8>, CacheEntry>,
    order: VecDeque<Vec<u8>>,
}

impl CacheCore {
    pub fn new(config: CacheConfig) -> Self {
        Self {
            config,
            entries: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    pub fn make_key(&self, query_bytes: &[u8], ecs: Option<&str>) -> Result<Vec<u8>, String> {
        let query = Message::from_vec(query_bytes).map_err(|err| err.to_string())?;
        if query.message_type() != MessageType::Query {
            return Err("dns message is not a query".into());
        }
        if query.op_code() != OpCode::Query {
            return Err("dns message opcode is not QUERY".into());
        }
        if query.queries().len() != 1 {
            return Err("dns message must contain exactly one question".into());
        }

        let question = &query.queries()[0];
        let qname = question.name().to_ascii();
        if qname.len() > u8::MAX as usize {
            return Err("qname is too long for cache key encoding".into());
        }

        let ecs = if self.config.enable_ecs {
            ecs.unwrap_or_default()
        } else {
            ""
        };
        if ecs.len() > u8::MAX as usize {
            return Err("ecs text is too long for cache key encoding".into());
        }

        let mut flags = 0_u8;
        if query.authentic_data() {
            flags |= 1;
        }
        if query.checking_disabled() {
            flags |= 1 << 1;
        }
        if query
            .extensions()
            .as_ref()
            .is_some_and(|extensions| extensions.flags().dnssec_ok)
        {
            flags |= 1 << 2;
        }

        let mut key = Vec::with_capacity(
            1 + 2 + 1 + qname.len() + if ecs.is_empty() { 0 } else { 1 + ecs.len() },
        );
        key.push(flags);
        let qtype = u16::from(question.query_type());
        key.push((qtype >> 8) as u8);
        key.push((qtype & 0xff) as u8);
        key.push(qname.len() as u8);
        key.extend_from_slice(qname.as_bytes());
        if !ecs.is_empty() {
            key.push(ecs.len() as u8);
            key.extend_from_slice(ecs.as_bytes());
        }
        Ok(key)
    }

    pub fn lookup(
        &self,
        query_bytes: &[u8],
        ecs: Option<&str>,
        now: SystemTime,
    ) -> Result<LookupResult, String> {
        let key = self.make_key(query_bytes, ecs)?;
        self.lookup_by_key(&key, now)
    }

    pub fn lookup_by_key(&self, key: &[u8], now: SystemTime) -> Result<LookupResult, String> {
        validate_key_bytes(key)?;
        let Some(entry) = self.entries.get(key) else {
            return Ok(LookupResult {
                state: LookupState::Miss,
                response: None,
                domain_set: None,
            });
        };

        if now >= entry.cache_expires_at {
            return Ok(LookupResult {
                state: LookupState::Miss,
                response: None,
                domain_set: None,
            });
        }

        let mut message = Message::from_vec(&entry.response).map_err(|err| err.to_string())?;

        if now < entry.msg_expires_at {
            let elapsed = now
                .duration_since(entry.stored_at)
                .unwrap_or_else(|_| Duration::from_secs(0))
                .as_secs() as u32;
            subtract_ttl(&mut message, elapsed);
            return Ok(LookupResult {
                state: LookupState::FreshHit,
                response: Some(message.to_vec().map_err(|err| err.to_string())?),
                domain_set: entry.domain_set.clone(),
            });
        }

        if self.config.lazy_cache_ttl > 0 {
            set_ttl(&mut message, EXPIRED_MSG_TTL);
            return Ok(LookupResult {
                state: LookupState::LazyHit,
                response: Some(message.to_vec().map_err(|err| err.to_string())?),
                domain_set: entry.domain_set.clone(),
            });
        }

        Ok(LookupResult {
            state: LookupState::Miss,
            response: None,
            domain_set: None,
        })
    }

    pub fn store_response(
        &mut self,
        query_bytes: &[u8],
        ecs: Option<&str>,
        response_bytes: &[u8],
        domain_set: Option<String>,
        now: SystemTime,
    ) -> Result<bool, String> {
        let key = self.make_key(query_bytes, ecs)?;
        self.store_response_by_key(&key, response_bytes, domain_set, now)
    }

    pub fn store_response_by_key(
        &mut self,
        key: &[u8],
        response_bytes: &[u8],
        domain_set: Option<String>,
        now: SystemTime,
    ) -> Result<bool, String> {
        validate_key_bytes(key)?;
        let mut response = Message::from_vec(response_bytes).map_err(|err| err.to_string())?;
        if response.truncated() {
            return Ok(false);
        }
        if self.contains_excluded_ip(&response) {
            return Ok(false);
        }

        let (msg_ttl, cache_ttl) = self.compute_ttls(&response);
        *response.extensions_mut() = None;
        let packed = response.to_vec().map_err(|err| err.to_string())?;

        let entry = CacheEntry {
            response: packed,
            stored_at: now,
            msg_expires_at: now + Duration::from_secs(msg_ttl as u64),
            cache_expires_at: now + Duration::from_secs(cache_ttl as u64),
            domain_set,
        };
        self.insert_entry(key.to_vec(), entry);
        Ok(true)
    }

    fn insert_entry(&mut self, key: Vec<u8>, entry: CacheEntry) {
        if !self.entries.contains_key(&key) {
            while self.entries.len() >= self.config.size.max(1) {
                let Some(old_key) = self.order.pop_front() else {
                    break;
                };
                if self.entries.remove(&old_key).is_some() {
                    break;
                }
            }
            self.order.push_back(key.clone());
        }

        self.entries.insert(key, entry);
    }

    fn compute_ttls(&self, response: &Message) -> (u32, u32) {
        let (mut msg_ttl, mut cache_ttl) = match response.response_code() {
            ResponseCode::NXDomain => (30, 30),
            ResponseCode::ServFail => (5, 5),
            ResponseCode::NoError => {
                let min_ttl = minimal_ttl(response);
                let message_ttl = if response.answers().is_empty() {
                    min_ttl.min(EMPTY_ANSWER_MAX_TTL)
                } else {
                    min_ttl
                };
                let cache_ttl = if self.config.lazy_cache_ttl > 0 {
                    self.config.lazy_cache_ttl
                } else {
                    message_ttl
                };
                (message_ttl, cache_ttl)
            }
            _ => (0, 0),
        };

        if msg_ttl == 0 {
            msg_ttl = MIN_CACHEABLE_TTL;
        }
        if cache_ttl == 0 {
            cache_ttl = MIN_CACHEABLE_TTL;
        }

        (msg_ttl, cache_ttl)
    }

    fn contains_excluded_ip(&self, response: &Message) -> bool {
        if self.config.exclude_ips.is_empty() {
            return false;
        }

        response.answers().iter().any(|record| {
            let ip = match record.data() {
                RData::A(ipv4) => Some(IpAddr::V4(ipv4.0)),
                RData::AAAA(ipv6) => Some(IpAddr::V6(ipv6.0)),
                _ => None,
            };

            ip.is_some_and(|ip| self.config.exclude_ips.iter().any(|net| net.contains(&ip)))
        })
    }

    pub fn flush(&mut self) {
        self.entries.clear();
        self.order.clear();
    }

    pub fn export_dump_bytes(&self, now: SystemTime) -> Result<Vec<u8>, String> {
        let mut encoder = flate2::GzBuilder::new()
            .filename(DUMP_HEADER)
            .write(Vec::new(), flate2::Compression::fast());

        let mut block = CacheDumpBlockPb {
            entries: Vec::new(),
        };
        for (key, entry) in &self.entries {
            if entry.cache_expires_at <= now {
                continue;
            }

            block.entries.push(CachedEntryPb {
                key: key.clone(),
                msg: entry.response.clone(),
                cache_expiration_time: system_time_to_unix(entry.cache_expires_at)?,
                msg_expiration_time: system_time_to_unix(entry.msg_expires_at)?,
                msg_stored_time: system_time_to_unix(entry.stored_at)?,
                domain_set: entry.domain_set.clone().unwrap_or_default(),
            });

            if block.entries.len() >= DUMP_BLOCK_SIZE {
                write_dump_block(&mut encoder, &mut block)?;
            }
        }

        if !block.entries.is_empty() {
            write_dump_block(&mut encoder, &mut block)?;
        }

        encoder.finish().map_err(|err| err.to_string())
    }

    pub fn import_dump_bytes(&mut self, payload: &[u8]) -> Result<usize, String> {
        let reader = Cursor::new(payload);
        let mut decoder = flate2::read::GzDecoder::new(reader);

        let header_name = decoder
            .header()
            .and_then(|h| h.filename())
            .map(|v| String::from_utf8_lossy(v).to_string())
            .unwrap_or_default();
        if header_name != DUMP_HEADER {
            return Err(format!(
                "invalid or old cache dump, header is {}, want {}",
                header_name, DUMP_HEADER
            ));
        }

        let mut entries_read = 0usize;
        loop {
            let mut len_buf = [0u8; 8];
            match decoder.read_exact(&mut len_buf) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(err) => return Err(format!("failed to read block header: {}", err)),
            }

            let block_len = u64::from_be_bytes(len_buf) as usize;
            if block_len > DUMP_MAXIMUM_BLOCK_LENGTH {
                return Err(format!(
                    "invalid header, block length is big, {}",
                    block_len
                ));
            }

            let mut block_payload = vec![0u8; block_len];
            decoder
                .read_exact(&mut block_payload)
                .map_err(|err| format!("failed to read block data: {}", err))?;

            let block = CacheDumpBlockPb::decode(block_payload.as_slice())
                .map_err(|err| format!("failed to decode block data: {}", err))?;
            entries_read += block.entries.len();

            for entry in block.entries {
                let cache_expires_at = unix_to_system_time(entry.cache_expiration_time)?;
                let msg_expires_at = unix_to_system_time(entry.msg_expiration_time)?;
                let stored_at = unix_to_system_time(entry.msg_stored_time)?;
                let domain_set = if entry.domain_set.is_empty() {
                    None
                } else {
                    Some(entry.domain_set)
                };

                self.insert_entry(
                    entry.key,
                    CacheEntry {
                        response: entry.msg,
                        stored_at,
                        msg_expires_at,
                        cache_expires_at,
                        domain_set,
                    },
                );
            }
        }

        Ok(entries_read)
    }
}

fn minimal_ttl(message: &Message) -> u32 {
    let mut min_ttl: Option<u32> = None;
    for record in message
        .answers()
        .iter()
        .chain(message.name_servers().iter())
        .chain(message.additionals().iter())
    {
        let ttl = record.ttl();
        min_ttl = Some(min_ttl.map_or(ttl, |current| current.min(ttl)));
    }

    min_ttl.unwrap_or(0)
}

fn set_ttl(message: &mut Message, ttl: u32) {
    for record in message.answers_mut() {
        record.set_ttl(ttl);
    }
    for record in message.name_servers_mut() {
        record.set_ttl(ttl);
    }
    for record in message.additionals_mut() {
        record.set_ttl(ttl);
    }
}

fn subtract_ttl(message: &mut Message, delta: u32) {
    for record in message.answers_mut() {
        let ttl = record.ttl();
        record.set_ttl(if ttl > delta { ttl - delta } else { 1 });
    }
    for record in message.name_servers_mut() {
        let ttl = record.ttl();
        record.set_ttl(if ttl > delta { ttl - delta } else { 1 });
    }
    for record in message.additionals_mut() {
        let ttl = record.ttl();
        record.set_ttl(if ttl > delta { ttl - delta } else { 1 });
    }
}

fn validate_key_bytes(key: &[u8]) -> Result<(), String> {
    if key.len() < 4 {
        return Err("cache key is too short".into());
    }
    let name_len = key[3] as usize;
    if key.len() < 4 + name_len {
        return Err("cache key has incomplete qname segment".into());
    }
    let mut offset = 4 + name_len;
    if offset < key.len() {
        let ecs_len = key[offset] as usize;
        offset += 1;
        if key.len() < offset + ecs_len {
            return Err("cache key has incomplete ecs segment".into());
        }
        offset += ecs_len;
    }
    if offset != key.len() {
        return Err("cache key has trailing bytes".into());
    }
    Ok(())
}

fn empty_lookup_result() -> MosdnsCacheLookupResult {
    MosdnsCacheLookupResult {
        status: -1,
        state: 0,
        response_ptr: std::ptr::null_mut(),
        response_len: 0,
        domain_set_ptr: std::ptr::null_mut(),
        domain_set_len: 0,
    }
}

fn empty_bytes_result() -> MosdnsCacheBytesResult {
    MosdnsCacheBytesResult {
        status: -1,
        ptr: std::ptr::null_mut(),
        len: 0,
    }
}

fn write_dump_block<W: Write>(writer: &mut W, block: &mut CacheDumpBlockPb) -> Result<(), String> {
    let data = block.encode_to_vec();
    let len = (data.len() as u64).to_be_bytes();
    writer.write_all(&len).map_err(|err| err.to_string())?;
    writer.write_all(&data).map_err(|err| err.to_string())?;
    block.entries.clear();
    Ok(())
}

fn unix_to_system_time(ts: i64) -> Result<SystemTime, String> {
    if ts < 0 {
        return Err("negative unix timestamp is not supported".into());
    }
    Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(ts as u64))
}

fn system_time_to_unix(ts: SystemTime) -> Result<i64, String> {
    ts.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .map_err(|_| "timestamp is before unix epoch".to_string())
}

unsafe fn bytes_from_parts<'a>(ptr: *const c_uchar, len: c_ulonglong) -> Result<&'a [u8], String> {
    let len = len as usize;
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err("received null pointer for non-empty byte slice".into());
    }
    Ok(slice::from_raw_parts(ptr, len))
}

fn parse_optional_utf8(bytes: &[u8]) -> Result<Option<&str>, String> {
    if bytes.is_empty() {
        return Ok(None);
    }
    std::str::from_utf8(bytes)
        .map(Some)
        .map_err(|err| format!("invalid utf8 payload: {err}"))
}

fn parse_unix_time(seconds: c_longlong) -> Result<SystemTime, String> {
    if seconds < 0 {
        return Err("negative unix timestamp is not supported".into());
    }
    Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(seconds as u64))
}

fn into_raw_parts(bytes: Vec<u8>) -> (*mut c_uchar, c_ulonglong) {
    let mut bytes = bytes;
    let len = bytes.len() as c_ulonglong;
    let ptr = bytes.as_mut_ptr();
    std::mem::forget(bytes);
    (ptr, len)
}

#[no_mangle]
pub extern "C" fn mosdns_cache_runtime_version() -> *const i8 {
    RUNTIME_VERSION.as_ptr().cast()
}

#[no_mangle]
pub extern "C" fn mosdns_cache_runtime_ping() -> c_int {
    0
}

#[no_mangle]
pub unsafe extern "C" fn mosdns_cache_new(
    size: c_ulonglong,
    lazy_cache_ttl: u32,
    enable_ecs: c_uchar,
    exclude_ips_ptr: *const c_uchar,
    exclude_ips_len: c_ulonglong,
) -> *mut CacheCore {
    let exclude_src = match bytes_from_parts(exclude_ips_ptr, exclude_ips_len) {
        Ok(v) => v,
        Err(_) => return std::ptr::null_mut(),
    };

    let exclude_text = match std::str::from_utf8(exclude_src) {
        Ok(v) => v,
        Err(_) => return std::ptr::null_mut(),
    };

    let mut exclude_ips = Vec::new();
    for token in exclude_text.split_whitespace() {
        if let Ok(net) = token.parse::<IpNet>() {
            exclude_ips.push(net);
        }
    }

    let config = CacheConfig {
        size: size as usize,
        lazy_cache_ttl,
        enable_ecs: enable_ecs != 0,
        exclude_ips,
    };

    Box::into_raw(Box::new(CacheCore::new(config)))
}

#[no_mangle]
pub unsafe extern "C" fn mosdns_cache_free(handle: *mut CacheCore) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

#[no_mangle]
pub unsafe extern "C" fn mosdns_cache_lookup(
    handle: *mut CacheCore,
    query_ptr: *const c_uchar,
    query_len: c_ulonglong,
    ecs_ptr: *const c_uchar,
    ecs_len: c_ulonglong,
    now_unix_sec: c_longlong,
) -> MosdnsCacheLookupResult {
    if handle.is_null() {
        return empty_lookup_result();
    }

    let query = match bytes_from_parts(query_ptr, query_len) {
        Ok(v) => v,
        Err(_) => return empty_lookup_result(),
    };
    let ecs_bytes = match bytes_from_parts(ecs_ptr, ecs_len) {
        Ok(v) => v,
        Err(_) => return empty_lookup_result(),
    };
    let ecs = match parse_optional_utf8(ecs_bytes) {
        Ok(v) => v,
        Err(_) => return empty_lookup_result(),
    };
    let now = match parse_unix_time(now_unix_sec) {
        Ok(v) => v,
        Err(_) => return empty_lookup_result(),
    };

    let core = &mut *handle;
    let result = match core.lookup(query, ecs, now) {
        Ok(v) => v,
        Err(_) => return empty_lookup_result(),
    };

    let (state, response_bytes, domain_set_bytes) = match result.state {
        LookupState::Miss => (0, None, None),
        LookupState::FreshHit => (
            1,
            result.response,
            result.domain_set.map(String::into_bytes),
        ),
        LookupState::LazyHit => (
            2,
            result.response,
            result.domain_set.map(String::into_bytes),
        ),
    };

    let (response_ptr, response_len) = response_bytes
        .map(into_raw_parts)
        .unwrap_or((std::ptr::null_mut(), 0));
    let (domain_set_ptr, domain_set_len) = domain_set_bytes
        .map(into_raw_parts)
        .unwrap_or((std::ptr::null_mut(), 0));

    MosdnsCacheLookupResult {
        status: 0,
        state,
        response_ptr,
        response_len,
        domain_set_ptr,
        domain_set_len,
    }
}

#[no_mangle]
pub unsafe extern "C" fn mosdns_cache_lookup_by_key(
    handle: *mut CacheCore,
    key_ptr: *const c_uchar,
    key_len: c_ulonglong,
    now_unix_sec: c_longlong,
) -> MosdnsCacheLookupResult {
    if handle.is_null() {
        return empty_lookup_result();
    }

    let key = match bytes_from_parts(key_ptr, key_len) {
        Ok(v) => v,
        Err(_) => return empty_lookup_result(),
    };
    let now = match parse_unix_time(now_unix_sec) {
        Ok(v) => v,
        Err(_) => return empty_lookup_result(),
    };

    let core = &mut *handle;
    let result = match core.lookup_by_key(key, now) {
        Ok(v) => v,
        Err(_) => return empty_lookup_result(),
    };

    let (state, response_bytes, domain_set_bytes) = match result.state {
        LookupState::Miss => (0, None, None),
        LookupState::FreshHit => (
            1,
            result.response,
            result.domain_set.map(String::into_bytes),
        ),
        LookupState::LazyHit => (
            2,
            result.response,
            result.domain_set.map(String::into_bytes),
        ),
    };

    let (response_ptr, response_len) = response_bytes
        .map(into_raw_parts)
        .unwrap_or((std::ptr::null_mut(), 0));
    let (domain_set_ptr, domain_set_len) = domain_set_bytes
        .map(into_raw_parts)
        .unwrap_or((std::ptr::null_mut(), 0));

    MosdnsCacheLookupResult {
        status: 0,
        state,
        response_ptr,
        response_len,
        domain_set_ptr,
        domain_set_len,
    }
}

#[no_mangle]
pub unsafe extern "C" fn mosdns_cache_store(
    handle: *mut CacheCore,
    query_ptr: *const c_uchar,
    query_len: c_ulonglong,
    ecs_ptr: *const c_uchar,
    ecs_len: c_ulonglong,
    response_ptr: *const c_uchar,
    response_len: c_ulonglong,
    domain_set_ptr: *const c_uchar,
    domain_set_len: c_ulonglong,
    now_unix_sec: c_longlong,
) -> c_int {
    if handle.is_null() {
        return -1;
    }

    let query = match bytes_from_parts(query_ptr, query_len) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let ecs_bytes = match bytes_from_parts(ecs_ptr, ecs_len) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let response = match bytes_from_parts(response_ptr, response_len) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let domain_set_bytes = match bytes_from_parts(domain_set_ptr, domain_set_len) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let now = match parse_unix_time(now_unix_sec) {
        Ok(v) => v,
        Err(_) => return -1,
    };

    let ecs = match parse_optional_utf8(ecs_bytes) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let domain_set = if domain_set_bytes.is_empty() {
        None
    } else {
        match std::str::from_utf8(domain_set_bytes) {
            Ok(v) => Some(v.to_string()),
            Err(_) => return -1,
        }
    };

    let core = &mut *handle;
    match core.store_response(query, ecs, response, domain_set, now) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(_) => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn mosdns_cache_store_by_key(
    handle: *mut CacheCore,
    key_ptr: *const c_uchar,
    key_len: c_ulonglong,
    response_ptr: *const c_uchar,
    response_len: c_ulonglong,
    domain_set_ptr: *const c_uchar,
    domain_set_len: c_ulonglong,
    now_unix_sec: c_longlong,
) -> c_int {
    if handle.is_null() {
        return -1;
    }

    let key = match bytes_from_parts(key_ptr, key_len) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let response = match bytes_from_parts(response_ptr, response_len) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let domain_set_bytes = match bytes_from_parts(domain_set_ptr, domain_set_len) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let now = match parse_unix_time(now_unix_sec) {
        Ok(v) => v,
        Err(_) => return -1,
    };

    let domain_set = if domain_set_bytes.is_empty() {
        None
    } else {
        match std::str::from_utf8(domain_set_bytes) {
            Ok(v) => Some(v.to_string()),
            Err(_) => return -1,
        }
    };

    let core = &mut *handle;
    match core.store_response_by_key(key, response, domain_set, now) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(_) => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn mosdns_cache_flush(handle: *mut CacheCore) -> c_int {
    if handle.is_null() {
        return -1;
    }
    let core = &mut *handle;
    core.flush();
    0
}

#[no_mangle]
pub unsafe extern "C" fn mosdns_cache_export_dump(
    handle: *mut CacheCore,
) -> MosdnsCacheBytesResult {
    if handle.is_null() {
        return empty_bytes_result();
    }

    let core = &mut *handle;
    match core.export_dump_bytes(SystemTime::now()) {
        Ok(bytes) => {
            let (ptr, len) = into_raw_parts(bytes);
            MosdnsCacheBytesResult {
                status: 0,
                ptr,
                len,
            }
        }
        Err(_) => empty_bytes_result(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn mosdns_cache_import_dump(
    handle: *mut CacheCore,
    dump_ptr: *const c_uchar,
    dump_len: c_ulonglong,
) -> c_int {
    if handle.is_null() {
        return -1;
    }
    let payload = match bytes_from_parts(dump_ptr, dump_len) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let core = &mut *handle;
    match core.import_dump_bytes(payload) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn mosdns_cache_free_buffer(ptr: *mut c_uchar, len: c_ulonglong) {
    if ptr.is_null() {
        return;
    }
    let len = len as usize;
    drop(Vec::from_raw_parts(ptr, len, len));
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use ipnet::IpNet;
    use std::net::Ipv4Addr;
    use std::time::{Duration, SystemTime};

    #[test]
    fn cache_key_includes_ecs_when_enabled() {
        let query = make_query("example.org.", RecordType::A);
        let cfg = CacheConfig {
            size: 128,
            lazy_cache_ttl: 30,
            enable_ecs: true,
            exclude_ips: Vec::new(),
        };
        let cache = CacheCore::new(cfg);

        let with_ecs = cache
            .make_key(&query.to_vec().unwrap(), Some("203.0.113.0/24"))
            .unwrap();
        let without_ecs = cache.make_key(&query.to_vec().unwrap(), None).unwrap();

        assert_ne!(with_ecs, without_ecs);
    }

    #[test]
    fn fresh_lookup_reduces_ttl() {
        let query = make_query("example.org.", RecordType::A);
        let response = make_a_response("example.org.", 120, Ipv4Addr::new(1, 1, 1, 1));
        let mut cache = CacheCore::new(CacheConfig {
            size: 128,
            lazy_cache_ttl: 30,
            enable_ecs: false,
            exclude_ips: Vec::new(),
        });
        let now = unix_time(10);

        assert!(cache
            .store_response(
                &query.to_vec().unwrap(),
                None,
                &response.to_vec().unwrap(),
                None,
                now
            )
            .unwrap());

        let lookup = cache
            .lookup(
                &query.to_vec().unwrap(),
                None,
                now + Duration::from_secs(20),
            )
            .unwrap();

        assert_eq!(lookup.state, LookupState::FreshHit);
        assert_eq!(answer_ttl(lookup.response.as_ref().unwrap()), 100);
    }

    #[test]
    fn lazy_lookup_rewrites_ttl_after_expiration() {
        let query = make_query("example.org.", RecordType::A);
        let response = make_a_response("example.org.", 30, Ipv4Addr::new(1, 1, 1, 1));
        let mut cache = CacheCore::new(CacheConfig {
            size: 128,
            lazy_cache_ttl: 600,
            enable_ecs: false,
            exclude_ips: Vec::new(),
        });
        let now = unix_time(10);

        assert!(cache
            .store_response(
                &query.to_vec().unwrap(),
                None,
                &response.to_vec().unwrap(),
                None,
                now
            )
            .unwrap());

        let lookup = cache
            .lookup(
                &query.to_vec().unwrap(),
                None,
                now + Duration::from_secs(45),
            )
            .unwrap();

        assert_eq!(lookup.state, LookupState::LazyHit);
        assert_eq!(answer_ttl(lookup.response.as_ref().unwrap()), 5);
    }

    #[test]
    fn excluded_ip_response_is_not_cached() {
        let query = make_query("example.org.", RecordType::A);
        let response = make_a_response("example.org.", 120, Ipv4Addr::new(203, 0, 113, 7));
        let mut cache = CacheCore::new(CacheConfig {
            size: 128,
            lazy_cache_ttl: 0,
            enable_ecs: false,
            exclude_ips: vec!["203.0.113.0/24".parse::<IpNet>().unwrap()],
        });
        let now = unix_time(10);

        let stored = cache
            .store_response(
                &query.to_vec().unwrap(),
                None,
                &response.to_vec().unwrap(),
                Some("SET".into()),
                now,
            )
            .unwrap();

        assert!(!stored);
        assert_eq!(
            cache
                .lookup(&query.to_vec().unwrap(), None, now + Duration::from_secs(1))
                .unwrap()
                .state,
            LookupState::Miss
        );
    }

    #[test]
    fn flush_clears_entries() {
        let query = make_query("example.org.", RecordType::A);
        let response = make_a_response("example.org.", 120, Ipv4Addr::new(1, 1, 1, 1));
        let mut cache = CacheCore::new(CacheConfig {
            size: 128,
            lazy_cache_ttl: 0,
            enable_ecs: false,
            exclude_ips: Vec::new(),
        });
        let now = unix_time(10);

        let stored = cache
            .store_response(
                &query.to_vec().unwrap(),
                None,
                &response.to_vec().unwrap(),
                None,
                now,
            )
            .unwrap();
        assert!(stored);

        cache.flush();

        let lookup = cache
            .lookup(&query.to_vec().unwrap(), None, now + Duration::from_secs(1))
            .unwrap();
        assert_eq!(lookup.state, LookupState::Miss);
    }

    fn make_query(name: &str, record_type: RecordType) -> Message {
        let mut message = Message::new();
        message
            .add_query(Query::query(Name::from_ascii(name).unwrap(), record_type))
            .set_id(42)
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Query);
        message
    }

    fn make_a_response(name: &str, ttl: u32, ip: Ipv4Addr) -> Message {
        let query = Query::query(Name::from_ascii(name).unwrap(), RecordType::A);
        let record = Record::from_rdata(query.name().clone(), ttl, RData::A(A(ip)));

        let mut message = Message::new();
        message
            .add_query(query)
            .add_answer(record)
            .set_id(42)
            .set_message_type(MessageType::Response)
            .set_op_code(OpCode::Query)
            .set_response_code(ResponseCode::NoError);
        message
    }

    fn answer_ttl(bytes: &[u8]) -> u32 {
        let msg = Message::from_vec(bytes).unwrap();
        msg.answers().first().unwrap().ttl()
    }

    fn unix_time(seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
    }
}
