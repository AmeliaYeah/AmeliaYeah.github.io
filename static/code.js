//copy a codeblock script
function copy_script(bttn) {
	function reset_button() {
		setTimeout(() => {
			bttn.innerText = "Copy";
		}, 1000);
	}

	//get the base
	var base = bttn.parentNode.parentNode;

	//get the codeblock, then get the second row in the table
	// (the text, not the line numbers)
	var cb = base.querySelectorAll("pre > code")[1];

	//if no clipboard, disregard
	if(!navigator.clipboard) {
		bttn.innerText = "Clipboard not allowed";
		reset_button();
		return;
	}

	//format the text
	//remove extra newlines that aren't needed
	var txt = cb.innerText.split("\n");
	var to_cpy = "";
	txt.forEach((t) => {
		if(t == "") return;
		to_cpy += t+"\n";
	})

	//try to copy
	navigator.clipboard.writeText(to_cpy).then(() => {
		bttn.innerText = "Copied!";
	}).catch(() => {
		bttn.innerText = "Failed to copy";
	}).finally(reset_button);
}