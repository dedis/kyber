package platform

import (
	"testing"

	"github.com/dedis/onet/log"
	"github.com/stretchr/testify/require"
)

func TestDeterlab_parseHosts(t *testing.T) {
	d := &Deterlab{}
	require.NotNil(t, d.parseHosts(""))
	require.NotNil(t, d.parseHosts(deterHostsErr1))
	require.NotNil(t, d.parseHosts(deterHostsErr2))

	log.ErrFatal(d.parseHosts(deterHosts1))
	require.Equal(t, 9, len(d.Virt))
	require.Equal(t, 9, len(d.Phys))

	log.ErrFatal(d.parseHosts(deterHosts2))
	require.Equal(t, 2, len(d.Virt))
	require.Equal(t, 2, len(d.Phys))
}

const deterHostsErr1 = `
Experiment: SAFER/LB-LLD
State: active

Virtual Lan/Link Info:
ID              Member/Proto    IP/Mask         Delay     BW (Kbs)  Loss Rate
--------------- --------------- --------------- --------- --------- ---------
lanclients      client-0:0      10.0.1.1        5.00      100000    0.00000000`

const deterHostsErr2 = `
Experiment: SAFER/LB-LLD
State: active

Virtual Lan/Link Info:
ID              Member/Proto    IP/Mask         Delay     BW (Kbs)  Loss Rate
--------------- --------------- --------------- --------- --------- ---------
lanclients      client-0:0      10.0.1.1        5.00      100000
                ethernet        255.255.255.0   5.00      100000    0.00000000`

const deterHosts1 = `
Experiment: SAFER/LB-LLD
State: active

Virtual Lan/Link Info:
ID              Member/Proto    IP/Mask         Delay     BW (Kbs)  Loss Rate
--------------- --------------- --------------- --------- --------- ---------
lanclients      client-0:0      10.0.1.1        5.00      100000    0.00000000
                ethernet        255.255.255.0   5.00      100000    0.00000000
lanclients      client-1:0      10.0.1.2        5.00      100000    0.00000000
                ethernet        255.255.255.0   5.00      100000    0.00000000
lanclients      client-2:0      10.0.1.3        5.00      100000    0.00000000
                ethernet        255.255.255.0   5.00      100000    0.00000000
lanclients      client-3:0      10.0.1.4        5.00      100000    0.00000000
                ethernet        255.255.255.0   5.00      100000    0.00000000
lanclients      client-4:0      10.0.1.5        5.00      100000    0.00000000
                ethernet        255.255.255.0   5.00      100000    0.00000000
lanclients      relay:0         10.0.1.254      5.00      100000    0.00000000
                ethernet        255.255.255.0   5.00      100000    0.00000000
lantrustees     relay:1         10.1.0.254      50.00     100000    0.00000000
                ethernet        255.255.255.0   50.00     100000    0.00000000
lantrustees     trustee-0:0     10.1.0.1        50.00     10000     0.00000000
                ethernet        255.255.255.0   50.00     10000     0.00000000
lantrustees     trustee-1:0     10.1.0.2        50.00     10000     0.00000000
                ethernet        255.255.255.0   50.00     10000     0.00000000
lantrustees     trustee-2:0     10.1.0.3        50.00     10000     0.00000000
                ethernet        255.255.255.0   50.00     10000     0.00000000

Physical Lan/Link Mapping:
ID              Member          IP              MAC                  NodeID
--------------- --------------- --------------- -------------------- ---------
lanclients      client-0:0      10.0.1.1        a0:36:9f:08:54:da    cpc7
                                                4/1 <-> 6/17         HP2e4
lanclients      client-1:0      10.0.1.2        a0:36:9f:09:27:fa    cpc86
                                                4/1 <-> 7/24         HP2e3
lanclients      client-2:0      10.0.1.3        a0:36:9f:08:58:26    cpc33
                                                4/1 <-> 8/23         HP2e2
lanclients      client-3:0      10.0.1.4        00:0e:0c:65:e0:31    bpc040
                                                0/1 <-> 4/8          Bhpod
lanclients      client-4:0      10.0.1.5        00:15:17:5d:32:a4    bpc174
                                                0/1 <-> 6/7          Bhp3
lanclients      relay:0         10.0.1.254      00:04:23:bb:25:aa    bpc083
                                                0/1 <-> 8/11         Bhpmd
lantrustees     relay:1         10.1.0.254      00:04:23:bb:25:ab    bpc083
                                                1/1 <-> 4/4          Bhpmd
lantrustees     trustee-0:0     10.1.0.1        a0:36:9f:09:27:dc    cpc38
                                                2/1 <-> 6/20         HP2e2
lantrustees     trustee-1:0     10.1.0.2        a0:36:9f:09:28:f6    cpc13
                                                4/1 <-> 4/11         HP2e4
lantrustees     trustee-2:0     10.1.0.3        d8:9d:67:ee:ff:71    hpc032
                                                5/1 <-> 1/23         HPS9e1

Virtual Queue Info:
ID              Member          Q Limit    Type    weight/min_th/max_th/linterm
--------------- --------------- ---------- ------- ----------------------------
lanclients      client-0:0      100 slots  Tail    0/0/0/0
lanclients      client-1:0      100 slots  Tail    0/0/0/0
lanclients      client-2:0      100 slots  Tail    0/0/0/0
lanclients      client-3:0      100 slots  Tail    0/0/0/0
lanclients      client-4:0      100 slots  Tail    0/0/0/0
lanclients      relay:0         100 slots  Tail    0/0/0/0
lantrustees     relay:1         100 slots  Tail    0/0/0/0
lantrustees     trustee-0:0     100 slots  Tail    0/0/0/0
lantrustees     trustee-1:0     100 slots  Tail    0/0/0/0
lantrustees     trustee-2:0     100 slots  Tail    0/0/0/0
`

const deterHosts2 = `
Experiment: SAFER/LB-LLD
State: active

Virtual Lan/Link Info:
ID              Member/Proto    IP/Mask         Delay     BW (Kbs)  Loss Rate
--------------- --------------- --------------- --------- --------- ---------
lanclients      client-0:0      10.0.1.1        5.00      100000    0.00000000
                ethernet        255.255.255.0   5.00      100000    0.00000000
lanclients      client-1:0      10.0.1.2        5.00      100000    0.00000000
                ethernet        255.255.255.0   5.00      100000    0.00000000`
