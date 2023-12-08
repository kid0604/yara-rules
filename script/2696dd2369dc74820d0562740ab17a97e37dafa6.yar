import "math"
import "pe"

rule AutoIt_alt_1
{
	meta:
		author = "_pusher_"
		date = "2016-07"
		description = "www.autoitscript.com/site/autoit/"
		os = "windows"
		filetype = "script"

	strings:
		$aa0 = "AutoIt has detected the stack has become corrupt.\n\nStack corruption typically occurs when either the wrong calling convention is used or when the function is called with the wrong number of arguments.\n\nAutoIt supports the __stdcall (WINAPI) and __cdecl calling conventions.  The __stdcall (WINAPI) convention is used by default but __cdecl can be used instead.  See the DllCall() documentation for details on changing the calling convention." wide ascii nocase
		$aa1 = "AutoIt Error" wide ascii nocase
		$aa2 = "Missing right bracket ')' in expression." wide ascii nocase
		$aa3 = "Missing operator in expression." wide ascii nocase
		$aa4 = "Unbalanced brackets in expression." wide ascii nocase
		$aa5 = "Error parsing function call." wide ascii nocase
		$aa6 = ">>>AUTOIT NO CMDEXECUTE<<<" wide ascii nocase
		$aa7 = "#requireadmin" wide ascii nocase
		$aa8 = "#OnAutoItStartRegister" wide ascii nocase
		$aa9 = "#notrayicon" wide ascii nocase
		$aa10 = "Cannot parse #include" wide ascii nocase

	condition:
		5 of ($aa*)
}
