use clickhouse::Row;
use serde::Serialize;
use std::time::Duration;

fn serialize_timestamp<S>(ts: &std::time::Duration, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    s.serialize_u64(ts.as_millis() as u64)
}

#[derive(Debug)]
pub enum Event {
    LinuxConsts(LinuxConstsEvent, u32),
    IoWait(IoWaitEvent),
    AioGetevents(AioGeteventsEvent),
    AioSubmit(AioSubmitEvent),
    AioFile(AioFileEvent),
    TcpDiscovery(TcpDiscoveryEvent),
    Vfs(VfsEvent),
    FutexWait(FutexWaitEvent),
    FutexWake(FutexWakeEvent),
    MuxioWait(MuxioWaitEvent),
    MuxioFile(MuxioFileEvent),
    SocketContext(SocketContextEvent),
    SocketInet(SocketInetEvent),
    SocketMap(SocketMapEvent),
    Taskstats(TaskstatsEvent),
    Docker(DockerEvent),
    K8s(K8sEvent),
    ProcessContext(ProcessContextEvent),
}

#[derive(Debug, Serialize, Row)]
pub struct LinuxConstsEvent {
    pub const_type: String,
    pub const_name: String,
    pub value: u32,
}

#[derive(Debug, Serialize, Row)]
pub struct IoWaitEvent {
    pub machine_id: u32,
    #[serde(serialize_with = "serialize_timestamp")]
    pub ts_s: Duration,
    pub pid: u32,
    pub tid: u32,
    pub part0: u64,
    pub bdev: u64,
    pub op: u8,
    pub total_time: u64,
    pub sector_cnt: u32,
    pub total_requests: u32,
    pub hist0: u32,
    pub hist1: u32,
    pub hist2: u32,
    pub hist3: u32,
    pub hist4: u32,
    pub hist5: u32,
    pub hist6: u32,
    pub hist7: u32,
}

#[derive(Debug, Serialize, Row)]
pub struct AioGeteventsEvent {
    pub machine_id: u32,
    #[serde(serialize_with = "serialize_timestamp")]
    pub ts_s: Duration,
    pub pid: u32,
    pub tid: u32,
    pub aioctx: u64,
    pub total_time: u64,
    pub total_requests: u64,
}

#[derive(Debug, Serialize, Row)]
pub struct AioSubmitEvent {
    pub machine_id: u32,
    #[serde(serialize_with = "serialize_timestamp")]
    pub ts_s: Duration,
    pub pid: u32,
    pub tid: u32,
    pub aioctx: u64,
    pub total_requests: u64,
}

#[derive(Debug, Serialize, Row)]
pub struct AioFileEvent {
    pub machine_id: u32,
    #[serde(serialize_with = "serialize_timestamp")]
    pub ts_s: Duration,
    pub aioctx: u64,
    pub isreg: u8,
    pub fs_magic: Option<u32>,
    pub device_id: Option<u32>,
    pub inode_id: Option<u64>,
    pub part0: Option<u64>,
    pub bdev: Option<u64>,
    pub mode: u8,
    pub hist0: u32,
    pub hist1: u32,
    pub hist2: u32,
    pub hist3: u32,
    pub hist4: u32,
    pub hist5: u32,
    pub hist6: u32,
    pub hist7: u32,
}

#[derive(Debug, Serialize, Row)]
pub struct TcpDiscoveryEvent {
    pub local_machine_id: u32,
    pub local_inode_id: u64,
    pub remote_machine_id: u32,
    pub remote_inode_id: u64,
    #[serde(serialize_with = "serialize_timestamp")]
    pub inserted_at: Duration,
}

#[derive(Debug, Serialize, Row)]
pub struct VfsEvent {
    pub machine_id: u32,
    #[serde(serialize_with = "serialize_timestamp")]
    pub ts_s: Duration,
    pub pid: u32,
    pub tid: u32,
    pub fs_magic: u32,
    pub device_id: u32,
    pub inode_id: u64,
    pub op: u8,
    pub total_time: u64,
    pub total_bytes: u64,
    pub total_requests: u32,
    pub hist0: u32,
    pub hist1: u32,
    pub hist2: u32,
    pub hist3: u32,
    pub hist4: u32,
    pub hist5: u32,
    pub hist6: u32,
    pub hist7: u32,
}

#[derive(Debug, Serialize, Row)]
pub struct FutexWaitEvent {
    pub machine_id: u32,
    #[serde(serialize_with = "serialize_timestamp")]
    pub ts_s: Duration,
    pub pid: u32,
    pub tid: u32,
    pub futex_key_addr: u64,
    pub futex_key_word: u64,
    pub futex_key_offset: u32,
    pub total_requests: u64,
    pub total_time: u64,
    pub hist0: u32,
    pub hist1: u32,
    pub hist2: u32,
    pub hist3: u32,
    pub hist4: u32,
    pub hist5: u32,
    pub hist6: u32,
    pub hist7: u32,
}

#[derive(Debug, Serialize, Row)]
pub struct FutexWakeEvent {
    pub machine_id: u32,
    #[serde(serialize_with = "serialize_timestamp")]
    pub ts_s: Duration,
    pub pid: u32,
    pub tid: u32,
    pub futex_key_addr: u64,
    pub futex_key_word: u64,
    pub futex_key_offset: u32,
    pub total_requests: u64,
    pub successful_count: u64,
}

#[derive(Debug, Serialize, Row)]
pub struct MuxioWaitEvent {
    pub machine_id: u32,
    #[serde(serialize_with = "serialize_timestamp")]
    pub ts_s: Duration,
    pub pid: u32,
    pub tid: u32,
    pub is_epoll: bool,
    pub poll_id: u64,
    pub total_time: u64,
    pub total_requests: u64,
}

#[derive(Debug, Serialize, Row)]
pub struct MuxioFileEvent {
    pub machine_id: u32,
    #[serde(serialize_with = "serialize_timestamp")]
    pub ts_s: Duration,
    pub poll_id: u64,
    pub fs_magic: u32,
    pub device_id: u32,
    pub inode_id: u64,
    pub mode: u8,
    pub hist0: u32,
    pub hist1: u32,
    pub hist2: u32,
    pub hist3: u32,
    pub hist4: u32,
    pub hist5: u32,
    pub hist6: u32,
    pub hist7: u32,
}

#[derive(Debug, Serialize, Row)]
pub struct SocketContextEvent {
    pub machine_id: u32,
    pub inode_id: u64,
    pub family: u16,
    #[serde(rename = "type")]
    pub type_: u16,
    pub protocol: u16,
}

#[derive(Debug, Serialize, Row)]
pub struct SocketInetEvent {
    pub machine_id: u32,
    pub inode_id: u64,
    pub netns_cookie: u64,
    pub src_address: String,
    pub src_port: u16,
    pub dst_address: String,
    pub dst_port: u16,
}

#[derive(Debug, Serialize, Row)]
pub struct SocketMapEvent {
    pub machine_id: u32,
    pub sock1_inode_id: u64,
    pub sock2_inode_id: u64,
}

#[derive(Debug, Serialize, Row)]
pub struct TaskstatsEvent {
    pub machine_id: u32,
    #[serde(serialize_with = "serialize_timestamp")]
    pub ts: Duration,
    pub pid: u32,
    pub tid: u32,
    pub comm: String,
    pub nvcsw: u64,
    pub nivcsw: u64,
    pub run_time_total: u64,
    pub rq_time_total: u64,
    pub rq_count: u64,
    pub blkio_time_total: u64,
    pub blkio_count: u64,
    pub uninterruptible_total: u64,
    pub freepages_time_total: u64,
    pub freepages_count: u64,
    pub thrashing_time_total: u64,
    pub thrashing_count: u64,
    pub swapin_time_total: u64,
    pub swapin_count: u64,
}

#[derive(Debug, Serialize, Row)]
pub struct DockerEvent {
    pub machine_id: u32,
    pub cgroup: String,
    pub id: String,
    pub name: Option<String>,
    pub image_name: Option<String>,
    pub image_hash: Option<String>,
}

#[derive(Debug, Serialize, Row)]
pub struct K8sEvent {
    pub machine_id: u32,
    pub cgroup: String,
    pub id: String,
    pub namespace: Option<String>,
    pub pod_name: Option<String>,
    pub container_name: Option<String>,
    pub image_name: String,
}

#[derive(Debug, Serialize, Row)]
pub struct ProcessContextEvent {
    pub machine_id: u32,
    pub pid: u32,
    pub cgroup: Option<String>,
    pub argv: String,
    pub exe: Option<String>,
}

impl Event {
    pub fn variant_name(&self) -> &'static str {
        match self {
            Event::LinuxConsts(_, _) => "LinuxConsts",
            Event::IoWait(_) => "IoWait",
            Event::AioGetevents(_) => "AioGetevents",
            Event::AioSubmit(_) => "AioSubmit",
            Event::AioFile(_) => "AioFile",
            Event::TcpDiscovery(_) => "TcpDiscovery",
            Event::Vfs(_) => "Vfs",
            Event::FutexWait(_) => "FutexWait",
            Event::FutexWake(_) => "FutexWake",
            Event::MuxioWait(_) => "MuxioWait",
            Event::MuxioFile(_) => "MuxioFile",
            Event::SocketContext(_) => "SocketContext",
            Event::SocketInet(_) => "SocketInet",
            Event::SocketMap(_) => "SocketMap",
            Event::Taskstats(_) => "Taskstats",
            Event::Docker(_) => "Docker",
            Event::K8s(_) => "K8s",
            Event::ProcessContext(_) => "ProcessContext",
        }
    }
}
