rule WaterPamola_stealjs_str
{
	meta:
		description = "Injection code from xss using water pamola"
		author = "JPCERT/CC Incident Response Group"
		hash = "af99c566c94366f0f172475feedeeaab87177e102c28e703c1f0eeb6f41a835e"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$str1 = "getSou("
		$str2 = "eval(function(p,a,c,k,"
		$str3 = "poRec"
		$str4 = "application/x-www-form-urlencoded"
		$str5 = "XMLHttpRequest"
		$str6 = "device_type_id"
		$str7 = "ownersstore"
		$str8 = "transactionid"
		$str9 = "admin_template"
		$str10 = "ec_ver"

	condition:
		6 of ($str*)
}
