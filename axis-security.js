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

			var device = {
				address: null,
				user: null,
				password: null,
				protocol: "http"
			}

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
					//options can be JSON string or object and must include name,password & priviliges
//					console.log(action, options);
					VapixWrapper.Account_Set( device, options, function(error, response){
						msg.error = error;
						msg.payload = response;
						node.send(msg);
					});
				break;

				case "Remove account":
					if( !options || typeof options === "string" || options.length === 0 ) {
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

