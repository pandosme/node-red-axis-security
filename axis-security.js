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
//					console.log(action,device,options);
					if( typeof options === "string" )
						options = JSON.parse(options);
					
					if( !options ) {
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
					if( typeof options === "string" )
						options = JSON.parse(options);
					if( typeof options !== "object") {
						msg.error = "Invalid input";
						msg.payload = "Set options object properties";
						node.send(msg);
						return;
					}
					var setting = null;
					var cgi = null;
					
					var numberOfSetttings = Object.keys(options).length;
					if( numberOfSetttings == 0 ) {
						msg.error = false;
						msg.payload = "OK";
						node.send(msg);
						return;
					}
					
					for( var name in options ) {
						switch( name ) {
							case "discovery":
								setting = options[name];
								if( setting === true ) {
									cgi = "/axis-cgi/param.cgi?action=update&Network.UPnP.Enabled=yes&Network.Bonjour.Enabled=yes&Network.ZeroConf.Enabled=yes&WebService.DiscoveryMode.Discoverable=Yes";
								} else {
									cgi = "/axis-cgi/param.cgi?action=update&Network.UPnP.Enabled=no&Network.Bonjour.Enabled=no&Network.ZeroConf.Enabled=no&WebService.DiscoveryMode.Discoverable=No";
								}
								VapixWrapper.CGI( device, cgi, function(error,response ) {
									msg.error = error;
									msg.payload = response;
									numberOfSetttings--;
									if( numberOfSetttings <= 0 ) {
										node.send(msg);
										return;
									}
								});
							break;
							case "maintenance":
								setting = options[name];
								if( setting === true ) {
									cgi = "/axis-cgi/param.cgi?action=update&Network.SSH.Enabled=yes&Network.FTP.Enabled=yes&root.System.EditCgi=yes";
								} else {
									cgi = "/axis-cgi/param.cgi?action=update&Network.SSH.Enabled=no&Network.FTP.Enabled=no&System.EditCgi=no";
								}
								VapixWrapper.CGI( device, cgi, function(error,response ) {
									msg.error = error;
									msg.payload = response;
									numberOfSetttings--;
									if( numberOfSetttings <= 0 ) {
										node.send(msg);
										return;
									}
								});
							break;
							case "forceHTTPS":
								setting = options[name];
								if( setting === true ) {
									cgi = "/axis-cgi/param.cgi?action=update&System.BoaGroupPolicy.admin=https&System.BoaGroupPolicy.operator=https&System.BoaGroupPolicy.viewer=https";
								} else {
									cgi = "/axis-cgi/param.cgi?action=update&System.BoaGroupPolicy.admin=both&System.BoaGroupPolicy.operator=both&System.BoaGroupPolicy.viewer=both";
								}
								VapixWrapper.CGI( device, cgi, function(error,response ) {
									msg.error = error;
									msg.payload = response;
									numberOfSetttings--;
									if( numberOfSetttings <= 0 ) {
										node.send(msg);
										return;
									}
								});
							break;
							default:
								numberOfSetttings--;
								if( numberOfSetttings <= 0 ) {
									node.send(msg);
									return;
								}
							break;
						}
					}
				break;
			
				
				case "Set IP whitelist":
				    var ipFormat = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

					if( typeof options === "string" )
						options = JSON.parse(options);
					
					if( !options ) {
						msg.error = "Invalid input";
						msg.payload = "Set whitelist options";
						node.send(msg);
						return;
					}

					var whitelist = "no";
					var list = "";
						
					if( Array.isArray(options) && options.length > 0 ) {
						if( !ipFormat.test(options[0]) ) {
							msg.error = "Invalid input";
							msg.payload = options[0] + " is invalid IP address";
							node.send(msg);
							return;
						}
						whitelist = "yes";
						list = options[0];
						for(var i = 1; i < options.length;i++) {
							if( !ipFormat.test(options[i]) ) {
								msg.error = "Invalid input";
								msg.payload = options[i] + " is invalid IP address";
								node.send(msg);
								return;
							}
							list += "%20" + options[i];
						}
					}
					var cgi = "/axis-cgi/param.cgi?action=update&root.Network.Filter.Enabled=" + whitelist;
					cgi += "&root.Network.Filter.Input.AcceptAddresses=" + list;
//					console.log(cgi);
					VapixWrapper.CGI( device, cgi, function(error,response ) {
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
			
				case "HTTPS":
					data = msg.payload;
					if( !data || typeof data !== "object" || !data.hasOwnProperty("cert") || !data.hasOwnProperty("key") ) {
						msg.error = "Invalid input";
						msg.payload = "Check certificate property syntax";
						node.send( msg );
						return;
					}
					data.cert = data.cert.replace("-----BEGIN CERTIFICATE-----","");
					data.cert = data.cert.replace("-----END CERTIFICATE-----","");
					data.key = data.key.replace("-----BEGIN RSA PRIVATE KEY-----","");
					data.key = data.key.replace("-----END RSA PRIVATE KEY-----","");
					var certID = "HTTPS_" + parseInt(new Date().getTime()/1000);
					var body = '<tds:LoadCertificateWithPrivateKey xmlns="http://www.onvif.org/ver10/device/wsdl"><CertificateWithPrivateKey>\n';
					body += '<tt:CertificateID>' + certID + '</tt:CertificateID>\n';
					body += '<tt:Certificate>\n<tt:Data>' + data.cert + '</tt:Data>\n</tt:Certificate>\n';
					body += '<tt:PrivateKey>\n<tt:Data>' + data.key + '</tt:Data>\n</tt:PrivateKey>\n';
					body += '</CertificateWithPrivateKey></tds:LoadCertificateWithPrivateKey>\n';
					VapixWrapper.SOAP( device, body, function(error,response){
						msg.error = error;
						msg.payload = response;
						if( error ) {
							msg.payload = "Cannot install TLS certificate";
							node.send(msg);
							return;
						}
						body = '<aweb:SetWebServerTlsConfiguration xmlns="http://www.axis.com/vapix/ws/webserver"><Configuration>';
						body += '<Tls>true</Tls>';
						body += '<aweb:ConnectionPolicies><aweb:Admin>HttpAndHttps</aweb:Admin></aweb:ConnectionPolicies>';
						body += '<aweb:Ciphers>';
						body += '  <acert:Cipher>ECDHE-ECDSA-AES128-GCM-SHA256</acert:Cipher>';
						body += '  <acert:Cipher>ECDHE-RSA-AES128-GCM-SHA256</acert:Cipher>';
						body += '  <acert:Cipher>ECDHE-ECDSA-AES256-GCM-SHA384</acert:Cipher>';
						body += '  <acert:Cipher>ECDHE-RSA-AES256-GCM-SHA384</acert:Cipher>';
						body += '  <acert:Cipher>ECDHE-ECDSA-CHACHA20-POLY1305</acert:Cipher>';
						body += '  <acert:Cipher>ECDHE-RSA-CHACHA20-POLY1305</acert:Cipher>';
						body += '  <acert:Cipher>DHE-RSA-AES128-GCM-SHA256</acert:Cipher>';
						body += '  <acert:Cipher>DHE-RSA-AES256-GCM-SHA384</acert:Cipher>';
						body += '</aweb:Ciphers>';
						body += '<aweb:CertificateSet><acert:Certificates>';
						body += '<acert:Id>' + certID + '</acert:Id>';
						body += '</acert:Certificates><acert:CACertificates></acert:CACertificates>';
						body += '<acert:TrustedCertificates></acert:TrustedCertificates>';
						body += '</aweb:CertificateSet></Configuration></aweb:SetWebServerTlsConfiguration>';
						VapixWrapper.SOAP( device, body, function(error,response){
							msg.error = error;
							msg.payload = "HTTPS set with certificate " + certID;
							if( error )
								msg.payload = "Certificate installed but HTTPS not set";
							else
								
							node.send(msg);
							return;
						});
					});
				break;

				case "802.1X EAP-TLS":
					data = msg.payload;
					if( !data || typeof data !== "object" ||
						!data.hasOwnProperty("cert") || !data.hasOwnProperty("key") || 
					    !data.hasOwnProperty("CA_name") || !data.hasOwnProperty("CA_cert") || 
						!data.hasOwnProperty("EAP_identity") || !data.hasOwnProperty("EAPOL_version") || 
						data.cert.length < 500 || data.key.length < 500 || data.CA_cert.length < 500
						) {
						msg.error = "Invalid input";
						msg.payload = "Check 802.1X property syntax";
						node.send( msg );
						return;
					}

					data.CA_cert = data.CA_cert.replace("-----BEGIN CERTIFICATE-----","");
					data.CA_cert = data.CA_cert.replace("-----END CERTIFICATE-----","");
					
					var body = '<tds:LoadCACertificates xmlns="http://www.onvif.org/ver10/device/wsdl">';
					body += '<CACertificate><tt:CertificateID>' + data.CA_name + '</tt:CertificateID>';
					body += '<tt:Certificate><tt:Data>' + data.CA_cert + '</tt:Data></tt:Certificate></CACertificate></tds:LoadCACertificates>';
					VapixWrapper.SOAP( device, body, function(error,response){
						msg.error = error;
						msg.payload = response;
						if( error ) {
							msg.payload = "Cannot install CA certificate";
							node.send(msg);
							return;
						}
						data.cert = data.cert.replace("-----BEGIN CERTIFICATE-----","");
						data.cert = data.cert.replace("-----END CERTIFICATE-----","");
						data.key = data.key.replace("-----BEGIN RSA PRIVATE KEY-----","");
						data.key = data.key.replace("-----END RSA PRIVATE KEY-----","");
						
						var certID = "802.1X_" + parseInt(new Date().getTime()/1000);
						var body = '<tds:LoadCertificateWithPrivateKey xmlns="http://www.onvif.org/ver10/device/wsdl"><CertificateWithPrivateKey>\n';
						body += '<tt:CertificateID>' + certID + '</tt:CertificateID>\n';
						body += '<tt:Certificate>\n<tt:Data>' + data.cert + '</tt:Data>\n</tt:Certificate>\n';
						body += '<tt:PrivateKey>\n<tt:Data>' + data.key + '</tt:Data>\n</tt:PrivateKey>\n';
						body += '</CertificateWithPrivateKey></tds:LoadCertificateWithPrivateKey>\n';
						VapixWrapper.SOAP( device, body, function(error,response){
							msg.error = error;
							msg.payload = response;
							if( error ) {
								msg.payload = "Cannot install client certificate";
								node.send(msg);
								return;
							}
					
							var body = '<tds:SetDot1XConfiguration xmlns="http://www.onvif.org/ver10/device/wsdl">';
							body += '<Dot1XConfiguration>';
							body += '<tt:Dot1XConfigurationToken>EAPTLS_WIRED</tt:Dot1XConfigurationToken>';
							body += '<tt:Identity>' + data.EAP_identity + '</tt:Identity>';
							body += '<tt:EAPMethod>13</tt:EAPMethod>';
							body += '<tt:EAPMethodConfiguration><tt:TLSConfiguration>';
							body += '<tt:CertificateID>' + certID + '</tt:CertificateID>';
							body += '</tt:TLSConfiguration></tt:EAPMethodConfiguration>';
							body += '<tt:CACertificateID>' + data.CA_name + '</tt:CACertificateID>';
							body += '</Dot1XConfiguration></tds:SetDot1XConfiguration>';
							VapixWrapper.SOAP( device, body, function(error,response){
								msg.error = error;
								msg.payload = response;
								if( error ) {
									msg.payload = "Cannot install 802.1X client certificate";
									node.send(msg);
									return;
								}
								var cgi = '/axis-cgi/param.cgi?action=update&Network.Interface.I0.dot1x.Enabled=yes&Network.Interface.I0.dot1x.EAPOLVersion=' + data.EAPOL_version;	
								VapixWrapper.CGI( device, cgi, function(error,response ) {
									msg.error = error;
									msg.payload = "802.1X is set";
									if(error)
										msg.payload = "Certififcates installed but could not enable 802.1X";
									node.send(msg);
								});
							});
						});
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
			name: {type:"text"},
			preset: {type:"axis-preset"},
			address: {type:"text"},
			action: { type:"text" },
			options: { type:"text" }
		}		
	});
}

