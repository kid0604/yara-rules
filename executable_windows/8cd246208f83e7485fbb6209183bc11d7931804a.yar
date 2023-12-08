rule BlackByte
{
	meta:
		author = "rivitna"
		family = "ransomware.hive"
		description = "BlackByte ransomware Windows payload"
		severity = 10
		score = 100
		os = "windows"
		filetype = "executable"

	strings:
		$h0 = { 83 E? 05 48 83 C? 01 88 4? FF 4? 39 ?? (74 | 75) ?? }
		$s0 = "\x00main.RSA\x00" ascii
		$s1 = "\x00main._Cfunc_Begin\x00" ascii
		$s2 = "\x00main._Cfunc_Inj\x00" ascii
		$s3 = "\x00main.Inja" ascii
		$s4 = "\x00main.SetWinVer\x00" ascii
		$s5 = "\x00main.DelShadows" ascii
		$s6 = "\x00main.StartNetworkS" ascii
		$s7 = "\x00main.EnableLink" ascii
		$s8 = "\x00main.EnableLongPaths" ascii
		$s9 = "\x00main.GrantAll" ascii
		$s10 = "\x00main.LanScan" ascii
		$s11 = "\x00main.SetupKey\x00" ascii
		$s12 = "\x00main.PbKey\x00" ascii
		$s13 = "\x00main.Pognali" ascii
		$s14 = "\x00main.ShowNote" ascii
		$s15 = "\x00main.MountDrives" ascii
		$s16 = "\x00main.StopAllsvc" ascii
		$s17 = "\x00main.GenDrives" ascii
		$s18 = "\x00main.ParsePC" ascii
		$s19 = "\x00main.GetAccess" ascii
		$s20 = "\x00main.KillHypers" ascii
		$s21 = "\x00main.ParseHypers" ascii
		$s22 = "\x00main.Aes256Encr\x00" ascii
		$s23 = "\x00main.Aes256Decr\x00" ascii

	condition:
		(( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550)) and ((1 of ($h*)) or (4 of ($s*)))
}
