rule src_ptheft_command
{
	meta:
		description = "Auto-generated rule - file command.js"
		author = "Pasquale Stirparo"
		reference = "not set"
		date = "2015-10-08"
		hash = "49c0e5400068924ff87729d9e1fece19acbfbd628d085f8df47b21519051b7f3"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "var lilogo = 'http://content.linkedin.com/etc/designs/linkedin/katy/global/clientlibs/img/logo.png';" fullword wide ascii
		$s1 = "dark=document.getElementById('darkenScreenObject'); " fullword wide ascii
		$s2 = "beef.execute(function() {" fullword wide ascii
		$s3 = "var logo  = 'http://www.youtube.com/yt/brand/media/image/yt-brand-standard-logo-630px.png';" fullword wide ascii
		$s4 = "description.text('Enter your Apple ID e-mail address and password');" fullword wide ascii
		$s5 = "sneakydiv.innerHTML= '<div id=\"edge\" '+edgeborder+'><div id=\"window_container\" '+windowborder+ '><div id=\"title_bar\" ' +ti" wide ascii
		$s6 = "var logo  = 'https://www.yammer.com/favicon.ico';" fullword wide ascii
		$s7 = "beef.net.send('<%= @command_url %>', <%= @command_id %>, 'answer='+answer);" fullword wide ascii
		$s8 = "var title = 'Session Timed Out <img src=\"' + lilogo + '\" align=right height=20 width=70 alt=\"LinkedIn\">';" fullword wide ascii
		$s9 = "var title = 'Session Timed Out <img src=\"' + logo + '\" align=right height=20 width=70 alt=\"YouTube\">';" fullword wide ascii
		$s10 = "var title = 'Session Timed Out <img src=\"' + logo + '\" align=right height=24 width=24 alt=\"Yammer\">';" fullword wide ascii
		$s11 = "var logobox = 'style=\"border:4px #84ACDD solid;border-radius:7px;height:45px;width:45px;background:#ffffff\"';" fullword wide ascii
		$s12 = "sneakydiv.innerHTML= '<br><img src=\\''+imgr+'\\' width=\\'80px\\' height\\'80px\\' /><h2>Your session has timed out!</h2><p>For" wide ascii
		$s13 = "inner.append(title, description, user,password);" fullword wide ascii
		$s14 = "sneakydiv.innerHTML= '<div id=\"window_container\" '+windowborder+ '><div id=\"windowmain\" ' +windowmain+ '><div id=\"title_bar" wide ascii
		$s15 = "sneakydiv.innerHTML= '<div id=\"window_container\" '+windowborder+ '><div id=\"windowmain\" ' +windowmain+ '><div id=\"title_bar" wide ascii
		$s16 = "answer = document.getElementById('uname').value+':'+document.getElementById('pass').value;" fullword wide ascii
		$s17 = "password.keydown(function(event) {" fullword wide ascii

	condition:
		13 of them
}
