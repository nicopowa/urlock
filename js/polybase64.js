(function() {

	"use strict";

	if(!Uint8Array.fromBase64) {

		Uint8Array.fromBase64 = function(string, options = {}) {

			let str = string.replace(
				/\s/g,
				""
			);

			if(options.alphabet === "base64url") {

				str = str.replace(
					/-/g,
					"+"
				)
				.replace(
					/_/g,
					"/"
				);
			
			}

			while(str.length % 4)
				str += "=";
			const bin = atob(str);

			return Uint8Array.from(
				bin,
				c =>
					c.charCodeAt(0)
			);
		
		};
	
	}

	if(!Uint8Array.prototype.toBase64) {

		Uint8Array.prototype.toBase64 = function(options = {}) {

			let bin = "";

			for(let i = 0; i < this.length; i += 8192) {

				bin += String.fromCharCode(...this.subarray(
					i,
					i + 8192
				));
			
			}
			let res = btoa(bin);

			if(options.alphabet === "base64url") {

				res = res.replace(
					/\+/g,
					"-"
				)
				.replace(
					/\//g,
					"_"
				)
				.replace(
					/=/g,
					""
				);
			
			}
			else if(options.omitPadding) {

				res = res.replace(
					/=/g,
					""
				);
			
			}

			return res;
		
		};
	
	}

})();
