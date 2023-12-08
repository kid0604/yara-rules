rule php_dns : webshell
{
	meta:
		description = "Laudanum Injector Tools - file dns.php"
		author = "Florian Roth"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "01d5d16d876c55d77e094ce2b9c237de43b21a16"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "$query = isset($_POST['query']) ? $_POST['query'] : '';" fullword ascii
		$s2 = "$result = dns_get_record($query, $types[$type], $authns, $addtl);" fullword ascii
		$s3 = "if ($_SERVER[\"REMOTE_ADDR\"] == $IP)" fullword ascii
		$s4 = "foreach (array_keys($types) as $t) {" fullword ascii

	condition:
		filesize <15KB and all of them
}
