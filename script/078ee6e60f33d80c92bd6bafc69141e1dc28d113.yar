rule md5_fd141197c89d27b30821f3de8627ac38
{
	meta:
		description = "Detects a specific string in PHP script that may indicate a web shell"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "if(isset($_GET['do'])){$g0='adminhtml/default/default/images'"

	condition:
		any of them
}
