//Copyright (c) 2021 Fred Juhlin

const VapixWrapper = require('vapix-wrapper');

module.exports = function(RED) {
	function Axis_Security(config) {
		RED.nodes.createNode(this,config);
		this.preset = config.preset;
		this.action = config.action;
		this.options = config.options;

		var node = this;
		node.on('input', function(msg) {
			node.status({});

			var device = {address: null,user: null,password: null,protocol: "http"}

			var preset = RED.nodes.getNode(node.preset);
			if( preset ) {
				device.address = preset.address;
				device.user = preset.credentials.user;
				device.password = preset.credentials.password;
				device.protocol = preset.protocol || "http";
			}
			if( msg.address ) device.address = msg.address;
			if( msg.user ) device.user = msg.user;
			if( msg.password ) device.password = msg.password;

			var action = msg.action || node.action;
			var options = node.options || msg.options;
			var data = node.data || msg.payload;

//			console.log("axis-security", {action: action,options: options,data: data});

			msg.error = false;
			switch( action ) {
				case "List accounts":
					VapixWrapper.Account_List( device,function(error, response){
						msg.error = error;
						msg.payload = response;
						node.send(msg);
					});
				break;

				case "Set account":
					if( !options || !(typeof options === "string" || typeof options === "object") ) {
						msg.error = "Invalid input";
						msg.payload = "Set account options (JSON or object)";
						node.send(msg);
						return;
					}
					VapixWrapper.Account_Set( device, options, function(error, response){
						msg.error = error;
						msg.payload = response;
						node.send(msg);
					});
				break;

				case "Remove account":
					if( !options || typeof options !== "string" || options.length === 0 ) {
						msg.error = "Invalid input";
						msg.payload = "Set option to account name";
						node.send(msg);
						return;
					}
					VapixWrapper.Account_Remove( device, options, function(error, response){
						msg.error = error;
						msg.payload = response;
						node.send(msg);
					});
				break;

				case "Set common hardening":
					if( !options || !(typeof options === "string" || typeof options === "object") ) {
						msg.error = "Invalid input";
						msg.payload = "Set account options (JSON or object)";
						node.send(msg);
						return;
					}
					if( typeof options === "string" )
						options = JSON.parse(options);
					
					if( !options || typeof options !== "object" ) {
						msg.error = "Invalid input";
						msg.payload = "Set account options (JSON or object)";
						node.send(msg);
						return;
					}
					
				
					node.warn( action + "is not yet implemented");
				break;
				
				case "Enforce HTTPS":
					node.warn( action + "is not yet implemented");
				break;
				
				case "Set IP whitelist":
/*				
				    var ipFormat = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
					var whitelist = "no";
					var list = "";
					if( Array.isArray(options) && options.length > 0 ) {
						if( !ipFormat.test(msg.payload[0]) ) {
							msg.error = "Invalid input");
							msg.payload = msg.payload[0] + " is invalid IP address";
							node.send(msg);
							return;
						}
						whitelist = "yes";
						list = msg.payload[0];
						for(var i = 1; i < msg.payload.length;i++) {
							if( !ipFormat.test(msg.payload[i]) ) {
								msg.error = "Invalid input");
								msg.payload = msg.payload[i] + " is invalid IP address";
								node.send(msg);
								return;
							}
							list += "%20" + msg.payload[i];
						}
					}
					var cgi = "/axis-cgi/param.cgi?action=update&root.Network.Filter.Enabled=" + whitelist;
					cgi += "&root.Network.Filter.Input.AcceptAddresses=" + list;
					VapixWrapper.CGI( device, cgi, function(error,response ) {
						msg.error = error;
						msg.payload = response;
						node.send(msg);
					});
*/					
				break;

				case "List certificates":
					VapixWrapper.Certificates_List( device, function(error, response){
						msg.error = error;
						msg.payload = response;
						node.send(msg);
					});
				break;
				
				case "Request CSR":
					if(!data) {
						msg.error = "Invalid input";
						msg.payload = "Missing CSR data";
						node.send(msg);
					}
					VapixWrapper.Certificates_CSR( device, data, function(error, response){
						msg.error = error;
						msg.payload = response;
						node.send(msg);
					});
				break;

				case "Install signed certificate":
					node.warn( action + "is not yet implemented");
				break;
				
				case "Install P12 certificate":
					node.warn( action + "is not yet implemented");
				break;
				
				default:
					node.warn( action + "is not yet implemented");
				break;
			}
        });
    }
	
    RED.nodes.registerType("axis-security", Axis_Security,{
		defaults: {
			preset: {type:"axis-preset"},
			address: {type:"text"},
			action: { type:"text" },
			options: { type:"text" }
		}		
	});
}

