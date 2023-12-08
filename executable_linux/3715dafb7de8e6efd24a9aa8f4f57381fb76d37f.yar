import "hash"
import "pe"

rule elf_REvil
{
	meta:
		description = "Detect the risk of Ransomware Sodinokibi Rule 8"
		detail = "detect the risk of elf REvil/Sodinokibi"
		hash1 = "3d375d0ead2b63168de86ca2649360d9dcff75b3e0ffa2cf1e50816ec92b3b7d"
		hash2 = "796800face046765bd79f267c56a6c93ee2800b76d7f38ad96e5acb92599fcd4"
		hash3 = "d6762eff16452434ac1acc127f082906cc1ae5b0ff026d0d4fe725711db47763"
		hash4 = "ea1872b2835128e3cb49a0bc27e4727ca33c4e6eba1e80422db19b505f965bc4"
		os = "linux"
		filetype = "executable"

	strings:
		$s1 = "uname -a && echo \" | \" && hostname" fullword ascii
		$s2 = "esxcli --formatter=csv --format-param=fields==\"WorldID,DisplayName\" vm process list | awk -F \"\\\"*,\\\"*\" '{system(\"esxcli" ascii
		$s3 = "esxcli --formatter=csv --format-param=fields==\"WorldID,DisplayName\" vm process list | awk -F \"\\\"*,\\\"*\" '{system(\"esxcli" ascii
		$s4 = "!!!BY DEFAULT THIS SOFTWARE USES 50 THREADS!!!" fullword ascii
		$s5 = "[%s] already encrypted" fullword ascii
		$s6 = "%d:%d: Comment not allowed here" fullword ascii
		$s7 = "json.txt" fullword ascii
		$s8 = "Error decoding user_id %d " fullword ascii
		$s9 = "Error read urandm line %d!" fullword ascii
		$s10 = "%d:%d: Unexpected EOF in block comment" fullword ascii
		$s11 = "%d:%d: Unexpected `%c` in comment opening sequence" fullword ascii
		$s12 = "File [%s] was encrypted" fullword ascii
		$s13 = "File [%s] was NOT encrypted" fullword ascii
		$s14 = "rand: try to read %hu but get %lu bytes" fullword ascii
		$s15 = "Using silent mode, if you on esxi - stop VMs manualy" fullword ascii
		$s16 = "Encrypting [%s]" fullword ascii
		$s17 = "Error decoding note_body %d " fullword ascii
		$s18 = "Error decoding sub_id %d " fullword ascii
		$s19 = "Error decoding master_pk %d " fullword ascii
		$s20 = "Error open urandm line %d!" fullword ascii
		$s21 = "%d:%d: EOF unexpected" fullword ascii
		$s22 = "fatal error malloc enc" fullword ascii
		$s23 = "iji iji iji iji ij|- - - - - -|ji iji ifi iji iji iji" fullword ascii
		$s24 = "iji iji iji iji ij| ENCRYPTED |ji iji ifi iji iji iji" fullword ascii
		$s25 = "Key inizialization error ... something wrong with config" fullword ascii
		$s26 = "ss kill --type=force --world-id=\" $1)}'" fullword ascii
		$s27 = "pkill -9 %s" fullword ascii
		$s28 = ".note.gnu.build-id" fullword ascii
		$s29 = "libpthread.so.0" fullword ascii
		$s30 = "File error " fullword ascii
		$s31 = "Path: %s " fullword ascii
		$s32 = "pthread_timedjoin_np" fullword ascii
		$s33 = "Error parse cfg" fullword ascii
		$s34 = "fatal error,master_pk size is bad %lu " fullword ascii
		$s35 = "[%s] is protected by os" fullword ascii
		$s36 = "n failurH" fullword ascii
		$s37 = ".eh_frame_hdr" fullword ascii
		$s38 = "fatal error, no cfg!" fullword ascii
		$s39 = "Error create note in dir %s" fullword ascii
		$s40 = "Error no json file!" fullword ascii
		$s41 = ".note.ABI-tag" fullword ascii
		$s42 = "--silent (-s) use for not stoping VMs mode" fullword ascii
		$x1 = "\",\"nname\":\"{EXT}-readme.txt\",\"rdmcnt\":" ascii
		$x2 = " without --path encrypts current dir" fullword ascii

	condition:
		( uint16(0)==0x457f and (8 of them and 1 of ($x*))) or ( all of them )
}
