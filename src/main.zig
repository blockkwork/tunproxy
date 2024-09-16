const std = @import("std");
const os = std.os;
const linux = os.linux;

const c = @cImport({
    @cInclude("linux/if.h");
    @cInclude("linux/if_tun.h");
    @cInclude("asm-generic/ioctl.h");
    @cInclude("sys/ioctl.h");
});

pub fn main() !void {
    const my_string = "tun2";
    const addr = [4]u8{ 127, 0, 0, 1 };
    _ = addr; // autofix

    const fd = try tun(@constCast(my_string));
    try mtu(8000, @constCast(my_string));
    // try set_ipv4(@constCast(my_string), addr, 1);
    const proxy_fd = try connect();
    try read(fd, proxy_fd);

    while (true) {}
}

pub fn connect() !linux.fd_t {
    const sockaddr = std.net.Address{ .in = std.net.Ip4Address.init([4]u8{ 127, 0, 0, 1 }, 1080) };

    const fd = linux.socket(linux.AF.INET, linux.SOCK.STREAM, 0);

    const ifd: linux.fd_t = @intCast(fd);

    if (linux.connect(ifd, &sockaddr, sockaddr.getOsSockLen()) != 0) {
        std.debug.print("connect failed\n", .{});
        return error.ConnectFailed;
    }

    const buf = [3]u8{ 0x05, 0x01, 0x00 };
    _ = linux.write(ifd, &buf, 3);

    var recv_buf: [1024]u8 = undefined;

    const n = linux.read(ifd, &recv_buf, recv_buf.len);
    _ = n; // autofix
    std.debug.print("{} {}\n", .{ recv_buf[0], recv_buf[1] });
    // std.debug.print("read {} bytes\n", .{n});

    return ifd;
}

const IPHeader = extern struct {
    version_ihl: u8,
    tos: u8,
    total_length: u16,
    id: u16,
    frag_offset: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    saddr: u32,
    daddr: u32,
};

const TCPHeader = extern struct {
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    data_offset: u8,
    flags: u8,
    window: u16,
    checksum: u16,
    urgent_ptr: u16,
};

const IPHeaderSize = 20;
const TCPHeaderSize = 20;

const IPPROTO_TCP = 6;
const HTTPS_PORT = 443;

pub fn read(fd: linux.fd_t, proxy_fd: linux.fd_t) !void {
    var buf: [1024]u8 = undefined;

    while (true) {
        const n = linux.read(fd, &buf, buf.len);
        std.debug.print("{} {} {} proto: {} \n", .{ buf[0], buf[1], buf[3], buf[9] });

        if (n < @sizeOf(IPHeader)) {
            std.log.debug("read ( {} ) less than header ( {} )", .{ n, @sizeOf(IPHeader) });
        }

        const iph: *const IPHeader = @alignCast(@ptrCast(&buf[0]));

        const ihl = iph.version_ihl & 0x0F;

        // const header_length: u32 = @floatFromInt(ihl);

        const hdr_len = blk: {
            const cast: u32 = @intCast(ihl);
            break :blk cast * 4;
        };
        _ = hdr_len; // autofix

        std.debug.print("IP Header:\n", .{});
        std.debug.print("Source IP: \n", .{});
        formatIP(iph.saddr);
        std.debug.print("Destination IP: \n", .{});
        formatIP(iph.daddr);
        std.debug.print("Protocol: {}\n", .{iph.protocol});

        switch (iph.protocol) {
            IPPROTO_TCP => {
                const tcph: *const TCPHeader = @alignCast(@ptrCast(&buf[20]));

                std.debug.print("TCP Header:\n", .{});
                std.debug.print("Source Port: {}\n", .{tcph.src_port});
                std.debug.print("Destination Port: {}\n", .{tcph.dst_port});
                std.debug.print("Sequence Number: {}\n", .{tcph.seq_num});
                std.debug.print("Acknowledgment Number: {}\n", .{tcph.ack_num});
                const data_offset = tcph.data_offset >> 4;
                if (data_offset < 5 or data_offset > 15) {
                    std.debug.print("Error: Invalid Data Offset: {}\n", .{data_offset});
                } else {
                    std.debug.print("Data Offset: {} bytes\n", .{data_offset * 4});
                }

                std.debug.print("Flags: 0x{}\n", .{tcph.flags});
                std.debug.print("Window Size: {}\n", .{tcph.window});
                std.debug.print("Checksum: 0x{}\n", .{tcph.checksum});
                std.debug.print("Urgent Pointer: {}\n", .{tcph.urgent_ptr});

                var proxy_buf: [10]u8 = undefined;

                proxy_buf[0] = 0x01;
                proxy_buf[1] = 0x00;
                proxy_buf[2] = 0x01;

                const dstip: []u8 = undefined;
                const dst = try std.fmt.bufPrint(dstip, "{d}.{d}.{d}.{d}\n", .{ (iph.daddr >> 24) & 0xFF, (iph.daddr >> 16) & 0xFF, (iph.daddr >> 8) & 0xFF, iph.daddr & 0xFF });
                proxy_buf[3] = dst[0];
                proxy_buf[4] = dst[1];
                proxy_buf[5] = dst[2];
                proxy_buf[6] = dst[3];

                std.debug.print("proxy buf: {s}\n", .{proxy_buf});
            },
            else => {
                std.debug.print("Unknown protocol: {}\n", .{iph.protocol});
            },
        }

        std.debug.print("WRITE TO PROXY: {}\n", .{linux.write(proxy_fd, &buf, buf.len)});

        const n2 = linux.read(proxy_fd, &buf, buf.len);
        std.debug.print("{s}\n", .{buf[0..n2]});

        std.debug.print("WRITE TO TUN: {}\n", .{linux.write(fd, &buf, buf.len)});
    }
}

pub fn tun(name: []u8) !linux.fd_t {
    const flags = linux.O{ .ACCMODE = .RDWR };

    var ifr: c.ifreq = undefined;

    ifr.ifr_ifru.ifru_flags = c.IFF_TUN | c.IFF_NO_PI;
    // var ifr: linux.ifreq = undefined;
    @memset(&ifr.ifr_ifrn.ifrn_name, 0);

    // ifr.ifru.flags = IFF_TUN | IFF_NO_PI;

    std.debug.print("before name: {s}\n", .{ifr.ifr_ifrn.ifrn_name});

    std.mem.copyBackwards(u8, &ifr.ifr_ifrn.ifrn_name, name[0..name.len]);

    std.debug.print("after name: {s}\n", .{ifr.ifr_ifrn.ifrn_name});

    const fd = linux.open("/dev/net/tun", flags, 0);
    std.debug.print("{}\n", .{fd});

    const ifr_ptr_as_usize: usize = @intFromPtr(&ifr);

    const res = linux.ioctl(@intCast(fd), c.TUNSETIFF, ifr_ptr_as_usize);
    std.debug.print("{}\n", .{res});

    // std.mem.copyBackwards(u8, name, &ifr.ifr_ifrn.ifrn_name);
    // @memcpy(name, &ifr.ifr_ifrn.ifrn_name);
    // // if (linux.ioctl(@intCast(fd), c.TUNSETIFF, @intFromPtr(&ifr)) < 0) {
    // //     std.debug.print("ioctl failed\n", .{});
    // }

    //  set mtu

    return @intCast(fd);
}

pub fn mtu(mtu_val: i32, tun_name: []u8) !void {
    var ifr: linux.ifreq = undefined;
    @memset(&ifr.ifrn.name, 0);
    ifr.ifru.mtu = mtu_val;

    std.mem.copyBackwards(u8, &ifr.ifrn.name, tun_name[0..tun_name.len]);

    const fd = linux.socket(linux.AF.INET, linux.SOCK.STREAM, 0);
    defer _ = linux.close(@intCast(fd));

    const res = linux.ioctl(@intCast(fd), c.SIOCSIFMTU, @intFromPtr(&ifr));
    std.debug.print("MTU:{}\n", .{res});

    // std.debug.print("fd: {}\n", .{fd});
}

fn formatIP(addr: u32) void {
    std.debug.print("{d}.{d}.{d}.{d}\n", .{ (addr >> 24) & 0xFF, (addr >> 16) & 0xFF, (addr >> 8) & 0xFF, addr & 0xFF });
}
