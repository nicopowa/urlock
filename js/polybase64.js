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

			const binary = atob(str);
			const bytes = new Uint8Array(binary.length);

			for(let i = 0; i < binary.length; i++) {

				bytes[i] = binary.charCodeAt(i);
			
			}

			return bytes;

		};

	}

	if(!Uint8Array.prototype.toBase64) {

		Uint8Array.prototype.toBase64 = function(options = {}) {

			let binary = "";

			for(let i = 0; i < this.length; i++) {

				binary += String.fromCharCode(this[i]);
			
			}

			let result = btoa(binary);

			if(options.alphabet === "base64url") {

				result = result.replace(
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

				result = result.replace(
					/=/g,
					""
				);
			
			}

			return result;

		};

	}

})();