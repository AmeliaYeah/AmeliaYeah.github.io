//get text inside a codeblock
function get_codeblock_txt(bttn) {
	//get the base
	var base = bttn.parentNode.parentNode.parentNode;

	//get the codeblock, then get the second row in the table
	// (the text, not the line numbers)
	var cb = base.querySelectorAll("pre > code")[1];

	//format the text
	//remove extra newlines that aren't needed
	var spans = cb.innerText.split("\n");
	var to_cpy = "";
	for(var i = 0; i < spans.length; i += 2) {
		to_cpy += spans[i]+"\n";
	}

	//return the text
	return to_cpy;
}

//copy from a codeblock
function copy_script(bttn) {
	//get the image
	var img = bttn.querySelectorAll("img")[0];

	//if no clipboard, disregard
	if(!navigator.clipboard) {
		img.src = "/icons/cantcopy.png"
		reset_button();
		return;
	}

	//try to copy
	navigator.clipboard.writeText(get_codeblock_txt(bttn)).then(() => {
		img.src = "/icons/copied.png";
	}).catch(() => {
		img.src = "/icons/cantcopy.png";
	}).finally(() => {
		setTimeout(() => {
			img.src = "/icons/copy.png"
		}, 1000);
	});
}

//download script
function download_script(bttn, filename) {
	//get the text
	var text = get_codeblock_txt(bttn);

	//download logic
	var pom = document.createElement('a');
	pom.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(text));
	pom.setAttribute('download', filename);
	pom.style.display = 'none';
	document.body.appendChild(pom);
	pom.click();
	document.body.removeChild(pom);
}