rule APT30_Generic_2
{
	meta:
		description = "FireEye APT30 Report Sample - from many files"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		super_rule = 1
		hash0 = "aba8b9fa213e5e2f1f0404d13fecc20ea8651b57"
		hash1 = "7f11f5c9475240e5dd2eea7726c9229972cffc1f"
		hash2 = "94d3f91d1e50ecea729617729013c3d143bf2c3e"
		hash3 = "7e516ec04f28c76d67b8111ddfe58bbd628362cc"
		hash4 = "6b27bc0b0460b0a25b45d897ed4f399106c284d9"
		hash5 = "6df5b4b3da0964153bad22fb1f69483ae8316655"
		hash6 = "b68bce61dfd8763c3003480ba4066b3cb1ef126e"
		hash7 = "cc124682246d098740cfa7d20aede850d49b6597"
		hash8 = "1ef415bca310575944934fc97b0aa720943ba512"
		hash9 = "0559ab9356dcc869da18b2c96f48b76478c472b3"
		hash10 = "f15272042a4f9324ad5de884bd50f4072f4bdde3"
		hash11 = "1d93d5f5463cdf85e3c22c56ed1381957f4efaac"
		hash12 = "b6f1fb0f8a2fb92a3c60e154f24cfbca1984529f"
		hash13 = "9967a99a1b627ddb6899919e32a0f544ea498b48"
		hash14 = "95a3c812ca0ad104f045b26c483495129bcf37ca"
		hash15 = "bde9a72b2113d18b4fa537cc080d8d8ba1a231e8"
		hash16 = "ce1f53e06feab1e92f07ed544c288bf39c6fce19"
		hash17 = "72dae031d885dbf492c0232dd1c792ab4785a2dc"
		hash18 = "a2ccba46e40d0fb0dd3e1dba160ecbb5440862ec"
		hash19 = "c8007b59b2d495029cdf5b7b8fc8a5a1f7aa7611"
		hash20 = "9c6f470e2f326a055065b2501077c89f748db763"
		hash21 = "af3e232559ef69bdf2ee9cd96434dcec58afbe5a"
		hash22 = "e72e67ba32946c2702b7662c510cc1242cffe802"
		hash23 = "8fc0b1618b61dce5f18eba01809301cb7f021b35"
		hash24 = "6a8159da055dac928ba7c98ea1cdbe6dfb4a3c22"
		hash25 = "47463412daf0b0a410d3ccbb7ea294db5ff42311"
		hash26 = "e6efa0ccfddda7d7d689efeb28894c04ebc72be2"
		hash27 = "43a3fc9a4fee43252e9a570492e4efe33043e710"
		hash28 = "7406ebef11ca9f97c101b37f417901c70ab514b1"
		hash29 = "53ed9b22084f89b4b595938e320f20efe65e0409"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "%s\\%s\\KB985109.log" fullword
		$s1 = "%s\\%s\\KB989109.log" fullword
		$s2 = "Opera.exe" fullword wide
		$s3 = "%s:All online success on %u!" fullword
		$s4 = "%s:list online success on %u!" fullword
		$s5 = "%s:All online fail!" fullword
		$s6 = "Copyright Opera Software 1995-" wide
		$s7 = "%s:list online fail!" fullword
		$s8 = "OnlineTmp.txt" fullword
		$s9 = "Opera Internet Browser" fullword wide
		$s12 = "Opera Software" fullword wide
		$s15 = "Check lan have done!!!" fullword
		$s16 = "List End." fullword

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
