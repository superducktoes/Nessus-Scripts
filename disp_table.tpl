%# disp_table.tpl
<p>The following policies are available for use:</p>	
<table border="1">  
%for r in policyRows:
<ul>
	<li> {{r['name']}}</li>
</ul>
%end

<p>The following scanners are available for use:</p>
<table border="1">
%for r in scannerRows:
<ul>
	<li> {{r['name']}} </li>
</ul>
%end

<form method="POST" action="/">
      IP: <input name="hosts" type="text" />
</form>

</table>