rule laudanum : webshell
{
	meta:
		description = "Laudanum Injector Tools - file laudanum.php"
		author = "Florian Roth"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "fd498c8b195967db01f68776ff5e36a06c9dfbfe"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "public function __activate()" fullword ascii
		$s2 = "register_activation_hook(__FILE__, array('WP_Laudanum', 'activate'));" fullword ascii

	condition:
		filesize <5KB and all of them
}
