import "math"

rule WEBSHELL_PHP_Generic_Eval_alt_3
{
	meta:
		description = "Generic PHP webshell which uses any eval/exec function in the same line with user input"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/01/07"
		modified = "2023-04-05"
		hash = "a61437a427062756e2221bfb6d58cd62439d09d9"
		hash = "90c5cc724ec9cf838e4229e5e08955eec4d7bf95"
		hash = "2b41abc43c5b6c791d4031005bf7c5104a98e98a00ee24620ce3e8e09a78e78f"
		hash = "5c68a0fa132216213b66a114375b07b08dc0cb729ddcf0a29bff9ca7a22eaaf4"
		hash = "de3c01f55d5346577922bbf449faaaaa1c8d1aaa64c01e8a1ee8c9d99a41a1be"
		hash = "124065176d262bde397b1911648cea16a8ff6a4c8ab072168d12bf0662590543"
		hash = "cd7450f3e5103e68741fd086df221982454fbcb067e93b9cbd8572aead8f319b"
		hash = "ab835ce740890473adf5cc804055973b926633e39c59c2bd98da526b63e9c521"
		hash = "31ff9920d401d4fbd5656a4f06c52f1f54258bc42332fc9456265dca7bb4c1ea"
		hash = "64e6c08aa0b542481b86a91cdf1f50c9e88104a8a4572a8c6bd312a9daeba60e"
		hash = "80e98e8a3461d7ba15d869b0641cdd21dd5b957a2006c3caeaf6f70a749ca4bb"
		hash = "93982b8df76080e7ba4520ae4b4db7f3c867f005b3c2f84cb9dff0386e361c35"
		hash = "51c2c8b94c4b8cce806735bcf6e5aa3f168f0f7addce47b699b9a4e31dc71b47"
		hash = "7a16311a371f03b29d5220484e7ecbe841cfaead4e73c17aa6a9c23b5d94544d"
		hash = "7ca5dec0515dd6f401cb5a52c313f41f5437fc43eb62ea4bcc415a14212d09e9"
		hash = "fd5f0f81204ca6ca6e93343500400d5853012e88254874fc9f62efe0fde7ab3c"
		hash = "883f48ed4e9646da078cabf6b8b4946d9f199660262502650f76450ecf60ddd5"
		hash = "6d042b6393669bb4d98213091cabe554ab192a6c916e86c04d06cc2a4ca92c00"
		hash = "dd5d8a9b4bb406e0b8f868165a1714fe54ffb18e621582210f96f6e5ae850b33"
		id = "79cfbd88-f6f7-5cba-a325-0a99962139ca"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$geval = /\b(exec|shell_exec|passthru|system|popen|proc_open|pcntl_exec|eval|assert)[\t ]{0,300}(\(base64_decode)?(\(stripslashes)?[\t ]{0,300}(\(trim)?[\t ]{0,300}\(\$(_POST|_GET|_REQUEST|_SERVER\s?\[['"]HTTP_|GLOBALS\[['"]_(POST|GET|REQUEST))/ wide ascii
		$gfp1 = "eval(\"return [$serialised_parameter"
		$gfp2 = "$this->assert(strpos($styles, $"
		$gfp3 = "$module = new $_GET['module']($_GET['scope']);"
		$gfp4 = "$plugin->$_POST['action']($_POST['id']);"
		$gfp5 = "$_POST[partition_by]($_POST["
		$gfp6 = "$object = new $_REQUEST['type']($_REQUEST['id']);"
		$gfp7 = "The above example code can be easily exploited by passing in a string such as"
		$gfp8 = "Smarty_Internal_Debug::start_render($_template);"
		$gfp9 = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
		$gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
		$gfp11 = "(eval (getenv \"EPROLOG\")))"
		$gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"
		$gfp_3 = " GET /"
		$gfp_4 = " POST /"

	condition:
		filesize <300KB and not ( any of ($gfp*)) and $geval
}
