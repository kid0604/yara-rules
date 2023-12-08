import "pe"
import "math"

rule EarthWormRule2
{
	meta:
		description = "Detect the risk of Malware EarthWorm Rule 2"
		os = "linux"
		filetype = "executable"

	strings:
		$elf = {7f 45 4c 46}
		$string_1 = "File data send OK!"
		$string_2 = "please set the target first"
		$string_3 = "It support various OS or CPU.For example"
		$string_4 = "xxx -l [lport] -n [name]"

	condition:
		$elf at 0 and 2 of them
}
