rule legion_777
{
	meta:
		author = "Daxda (https://github.com/Daxda)"
		date = "2016/6/6"
		description = "Detects an UPX-unpacked .777 ransomware binary."
		ref = "https://github.com/Daxda/malware-analysis/tree/master/malware_samples/legion"
		category = "Ransomware"
		sample = "SHA256: 14d22359e76cf63bf17268cad24bac03663c8b2b8028b869f5cec10fe3f75548"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "http://tuginsaat.com/wp-content/themes/twentythirteen/stats.php"
		$s2 = "read_this_file.txt" wide
		$s3 = "seven_legion@india.com"
		$s4 = {46 4f 52 20 44 45 43 52 59 50 54 20 46 49 4c 45 53 0d 0a 53 45 4e 44 20 4f
               4e 45 20 46 49 4c 45 20 49 4e 20 45 2d 4d 41 49 4c 0d 0a 73 65 76 65 6e 5f
               6c 65 67 69 6f 6e 40 69 6e 64 69 61 2e 63 6f 6d }
		$s5 = "%s._%02i-%02i-%02i-%02i-%02i-%02i_$%s$.777"

	condition:
		4 of ($s*)
}
