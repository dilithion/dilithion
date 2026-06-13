// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license
// AUTO-GENERATED FILE - DO NOT EDIT DIRECTLY
// Generated from website/wallet.html by scripts/gen-embedded-html.sh

#ifndef DILITHION_API_WALLET_HTML_H
#define DILITHION_API_WALLET_HTML_H

#include <string>

inline const std::string& GetWalletHTML() {
    static const std::string html = R"WALLET_HTML(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <!-- wallet-rpc-login-restore: same-origin RPC session token.
         When this page is served BY a Dilithion node, the node replaces the
         placeholder below with a freshly-minted, server-validated session token.
         The wallet uses it as its RPC credential (replacing the old rpc:rpc).
         If the file is opened directly (not served by a node), the placeholder
         stays as the literal sentinel and the wallet falls back to the
         user-supplied rpcuser/rpcpassword fields. -->
    <meta name="dilithion-rpc-token" content="__DILITHION_RPC_SESSION_TOKEN__">
    <!-- dilv-node-wallet-csp-origin: when served BY a node, the node replaces
         this placeholder with its chain ("dil" or "dilv") so the wallet's chain
         identity (units, and chainId for tx signing) is AUTHORITATIVE rather
         than guessed from the RPC port — correct even on a custom --rpcport. If
         opened from disk / not served by a node, the sentinel stays and the
         wallet falls back to deriving the chain from the origin port. -->
    <meta name="dilithion-chain" content="__DILITHION_CHAIN__">
    <title>Dilithion Web Wallet</title>
    <link rel="icon" type="image/x-icon" href="favicon.ico">
    <!-- PWA -->
    <link rel="manifest" href="manifest.json">
    <meta name="theme-color" content="#C8A24E">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <meta name="apple-mobile-web-app-title" content="Dilithion">
    <link rel="apple-touch-icon" href="dilithion-logo-200.png">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=DM+Serif+Display&family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <!-- QRCode.js for QR generation (embedded for offline support) -->
    <script>!function(t){if("object"==typeof exports&&"undefined"!=typeof module)module.exports=t();else if("function"==typeof define&&define.amd)define([],t);else{var e;e="undefined"!=typeof window?window:"undefined"!=typeof global?global:"undefined"!=typeof self?self:this,e.QRCode=t()}}(function(){return function(){function t(e,r,n){function o(a,u){if(!r[a]){if(!e[a]){var s="function"==typeof require&&require;if(!u&&s)return s(a,!0);if(i)return i(a,!0);var f=new Error("Cannot find module '"+a+"'");throw f.code="MODULE_NOT_FOUND",f}var l=r[a]={exports:{}};e[a][0].call(l.exports,function(t){return o(e[a][1][t]||t)},l,l.exports,t,e,r,n)}return r[a].exports}for(var i="function"==typeof require&&require,a=0;a<n.length;a++)o(n[a]);return o}return t}()({1:[function(t,e,r){var n=t("./utils").getSymbolSize;r.getRowColCoords=function(t){if(1===t)return[];for(var e=Math.floor(t/7)+2,r=n(t),o=145===r?26:2*Math.ceil((r-13)/(2*e-2)),i=[r-7],a=1;a<e-1;a++)i[a]=i[a-1]-o;return i.push(6),i.reverse()},r.getPositions=function(t){for(var e=[],n=r.getRowColCoords(t),o=n.length,i=0;i<o;i++)for(var a=0;a<o;a++)0===i&&0===a||0===i&&a===o-1||i===o-1&&0===a||e.push([n[i],n[a]]);return e}},{"./utils":20}],2:[function(t,e,r){function n(t){this.mode=o.ALPHANUMERIC,this.data=t}var o=t("./mode"),i=["0","1","2","3","4","5","6","7","8","9","A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z"," ","$","%","*","+","-",".","/",":"];n.getBitsLength=function(t){return 11*Math.floor(t/2)+t%2*6},n.prototype.getLength=function(){return this.data.length},n.prototype.getBitsLength=function(){return n.getBitsLength(this.data.length)},n.prototype.write=function(t){var e;for(e=0;e+2<=this.data.length;e+=2){var r=45*i.indexOf(this.data[e]);r+=i.indexOf(this.data[e+1]),t.put(r,11)}this.data.length%2&&t.put(i.indexOf(this.data[e]),6)},e.exports=n},{"./mode":13}],3:[function(t,e,r){function n(){this.buffer=[],this.length=0}n.prototype={get:function(t){var e=Math.floor(t/8);return 1==(this.buffer[e]>>>7-t%8&1)},put:function(t,e){for(var r=0;r<e;r++)this.putBit(1==(t>>>e-r-1&1))},getLengthInBits:function(){return this.length},putBit:function(t){var e=Math.floor(this.length/8);this.buffer.length<=e&&this.buffer.push(0),t&&(this.buffer[e]|=128>>>this.length%8),this.length++}},e.exports=n},{}],4:[function(t,e,r){function n(t){if(!t||t<1)throw new Error("BitMatrix size must be defined and greater than 0");this.size=t,this.data=new o(t*t),this.data.fill(0),this.reservedBit=new o(t*t),this.reservedBit.fill(0)}var o=t("../utils/buffer");n.prototype.set=function(t,e,r,n){var o=t*this.size+e;this.data[o]=r,n&&(this.reservedBit[o]=!0)},n.prototype.get=function(t,e){return this.data[t*this.size+e]},n.prototype.xor=function(t,e,r){this.data[t*this.size+e]^=r},n.prototype.isReserved=function(t,e){return this.reservedBit[t*this.size+e]},e.exports=n},{"../utils/buffer":27}],5:[function(t,e,r){function n(t){this.mode=i.BYTE,this.data=new o(t)}var o=t("../utils/buffer"),i=t("./mode");n.getBitsLength=function(t){return 8*t},n.prototype.getLength=function(){return this.data.length},n.prototype.getBitsLength=function(){return n.getBitsLength(this.data.length)},n.prototype.write=function(t){for(var e=0,r=this.data.length;e<r;e++)t.put(this.data[e],8)},e.exports=n},{"../utils/buffer":27,"./mode":13}],6:[function(t,e,r){var n=t("./error-correction-level"),o=[1,1,1,1,1,1,1,1,1,1,2,2,1,2,2,4,1,2,4,4,2,4,4,4,2,4,6,5,2,4,6,6,2,5,8,8,4,5,8,8,4,5,8,11,4,8,10,11,4,9,12,16,4,9,16,16,6,10,12,18,6,10,17,16,6,11,16,19,6,13,18,21,7,14,21,25,8,16,20,25,8,17,23,25,9,17,23,34,9,18,25,30,10,20,27,32,12,21,29,35,12,23,34,37,12,25,34,40,13,26,35,42,14,28,38,45,15,29,40,48,16,31,43,51,17,33,45,54,18,35,48,57,19,37,51,60,19,38,53,63,20,40,56,66,21,43,59,70,22,45,62,74,24,47,65,77,25,49,68,81],i=[7,10,13,17,10,16,22,28,15,26,36,44,20,36,52,64,26,48,72,88,36,64,96,112,40,72,108,130,48,88,132,156,60,110,160,192,72,130,192,224,80,150,224,264,96,176,260,308,104,198,288,352,120,216,320,384,132,240,360,432,144,280,408,480,168,308,448,532,180,338,504,588,196,364,546,650,224,416,600,700,224,442,644,750,252,476,690,816,270,504,750,900,300,560,810,960,312,588,870,1050,336,644,952,1110,360,700,1020,1200,390,728,1050,1260,420,784,1140,1350,450,812,1200,1440,480,868,1290,1530,510,924,1350,1620,540,980,1440,1710,570,1036,1530,1800,570,1064,1590,1890,600,1120,1680,1980,630,1204,1770,2100,660,1260,1860,2220,720,1316,1950,2310,750,1372,2040,2430];r.getBlocksCount=function(t,e){switch(e){case n.L:return o[4*(t-1)+0];case n.M:return o[4*(t-1)+1];case n.Q:return o[4*(t-1)+2];case n.H:return o[4*(t-1)+3];default:return}},r.getTotalCodewordsCount=function(t,e){switch(e){case n.L:return i[4*(t-1)+0];case n.M:return i[4*(t-1)+1];case n.Q:return i[4*(t-1)+2];case n.H:return i[4*(t-1)+3];default:return}}},{"./error-correction-level":7}],7:[function(t,e,r){function n(t){if("string"!=typeof t)throw new Error("Param is not a string");switch(t.toLowerCase()){case"l":case"low":return r.L;case"m":case"medium":return r.M;case"q":case"quartile":return r.Q;case"h":case"high":return r.H;default:throw new Error("Unknown EC Level: "+t)}}r.L={bit:1},r.M={bit:0},r.Q={bit:3},r.H={bit:2},r.isValid=function(t){return t&&void 0!==t.bit&&t.bit>=0&&t.bit<4},r.from=function(t,e){if(r.isValid(t))return t;try{return n(t)}catch(t){return e}}},{}],8:[function(t,e,r){var n=t("./utils").getSymbolSize;r.getPositions=function(t){var e=n(t);return[[0,0],[e-7,0],[0,e-7]]}},{"./utils":20}],9:[function(t,e,r){var n=t("./utils"),o=n.getBCHDigit(1335);r.getEncodedBits=function(t,e){for(var r=t.bit<<3|e,i=r<<10;n.getBCHDigit(i)-o>=0;)i^=1335<<n.getBCHDigit(i)-o;return 21522^(r<<10|i)}},{"./utils":20}],10:[function(t,e,r){var n=t("../utils/buffer"),o=new n(512),i=new n(256);!function(){for(var t=1,e=0;e<255;e++)o[e]=t,i[t]=e,256&(t<<=1)&&(t^=285);for(e=255;e<512;e++)o[e]=o[e-255]}(),r.log=function(t){if(t<1)throw new Error("log("+t+")");return i[t]},r.exp=function(t){return o[t]},r.mul=function(t,e){return 0===t||0===e?0:o[i[t]+i[e]]}},{"../utils/buffer":27}],11:[function(t,e,r){function n(t){this.mode=o.KANJI,this.data=t}var o=t("./mode"),i=t("./utils");n.getBitsLength=function(t){return 13*t},n.prototype.getLength=function(){return this.data.length},n.prototype.getBitsLength=function(){return n.getBitsLength(this.data.length)},n.prototype.write=function(t){var e;for(e=0;e<this.data.length;e++){var r=i.toSJIS(this.data[e]);if(r>=33088&&r<=40956)r-=33088;else{if(!(r>=57408&&r<=60351))throw new Error("Invalid SJIS character: "+this.data[e]+"\nMake sure your charset is UTF-8");r-=49472}r=192*(r>>>8&255)+(255&r),t.put(r,13)}},e.exports=n},{"./mode":13,"./utils":20}],12:[function(t,e,r){function n(t,e,n){switch(t){case r.Patterns.PATTERN000:return(e+n)%2==0;case r.Patterns.PATTERN001:return e%2==0;case r.Patterns.PATTERN010:return n%3==0;case r.Patterns.PATTERN011:return(e+n)%3==0;case r.Patterns.PATTERN100:return(Math.floor(e/2)+Math.floor(n/3))%2==0;case r.Patterns.PATTERN101:return e*n%2+e*n%3==0;case r.Patterns.PATTERN110:return(e*n%2+e*n%3)%2==0;case r.Patterns.PATTERN111:return(e*n%3+(e+n)%2)%2==0;default:throw new Error("bad maskPattern:"+t)}}r.Patterns={PATTERN000:0,PATTERN001:1,PATTERN010:2,PATTERN011:3,PATTERN100:4,PATTERN101:5,PATTERN110:6,PATTERN111:7};var o={N1:3,N2:3,N3:40,N4:10};r.isValid=function(t){return null!=t&&""!==t&&!isNaN(t)&&t>=0&&t<=7},r.from=function(t){return r.isValid(t)?parseInt(t,10):void 0},r.getPenaltyN1=function(t){for(var e=t.size,r=0,n=0,i=0,a=null,u=null,s=0;s<e;s++){n=i=0,a=u=null;for(var f=0;f<e;f++){var l=t.get(s,f);l===a?n++:(n>=5&&(r+=o.N1+(n-5)),a=l,n=1),l=t.get(f,s),l===u?i++:(i>=5&&(r+=o.N1+(i-5)),u=l,i=1)}n>=5&&(r+=o.N1+(n-5)),i>=5&&(r+=o.N1+(i-5))}return r},r.getPenaltyN2=function(t){for(var e=t.size,r=0,n=0;n<e-1;n++)for(var i=0;i<e-1;i++){var a=t.get(n,i)+t.get(n,i+1)+t.get(n+1,i)+t.get(n+1,i+1);4!==a&&0!==a||r++}return r*o.N2},r.getPenaltyN3=function(t){for(var e=t.size,r=0,n=0,i=0,a=0;a<e;a++){n=i=0;for(var u=0;u<e;u++)n=n<<1&2047|t.get(a,u),u>=10&&(1488===n||93===n)&&r++,i=i<<1&2047|t.get(u,a),u>=10&&(1488===i||93===i)&&r++}return r*o.N3},r.getPenaltyN4=function(t){for(var e=0,r=t.data.length,n=0;n<r;n++)e+=t.data[n];return Math.abs(Math.ceil(100*e/r/5)-10)*o.N4},r.applyMask=function(t,e){for(var r=e.size,o=0;o<r;o++)for(var i=0;i<r;i++)e.isReserved(i,o)||e.xor(i,o,n(t,i,o))},r.getBestMask=function(t,e){for(var n=Object.keys(r.Patterns).length,o=0,i=1/0,a=0;a<n;a++){e(a),r.applyMask(a,t);var u=r.getPenaltyN1(t)+r.getPenaltyN2(t)+r.getPenaltyN3(t)+r.getPenaltyN4(t);r.applyMask(a,t),u<i&&(i=u,o=a)}return o}},{}],13:[function(t,e,r){function n(t){if("string"!=typeof t)throw new Error("Param is not a string");switch(t.toLowerCase()){case"numeric":return r.NUMERIC;case"alphanumeric":return r.ALPHANUMERIC;case"kanji":return r.KANJI;case"byte":return r.BYTE;default:throw new Error("Unknown mode: "+t)}}var o=t("./version-check"),i=t("./regex");r.NUMERIC={id:"Numeric",bit:1,ccBits:[10,12,14]},r.ALPHANUMERIC={id:"Alphanumeric",bit:2,ccBits:[9,11,13]},r.BYTE={id:"Byte",bit:4,ccBits:[8,16,16]},r.KANJI={id:"Kanji",bit:8,ccBits:[8,10,12]},r.MIXED={bit:-1},r.getCharCountIndicator=function(t,e){if(!t.ccBits)throw new Error("Invalid mode: "+t);if(!o.isValid(e))throw new Error("Invalid version: "+e);return e>=1&&e<10?t.ccBits[0]:e<27?t.ccBits[1]:t.ccBits[2]},r.getBestModeForData=function(t){return i.testNumeric(t)?r.NUMERIC:i.testAlphanumeric(t)?r.ALPHANUMERIC:i.testKanji(t)?r.KANJI:r.BYTE},r.toString=function(t){if(t&&t.id)return t.id;throw new Error("Invalid mode")},r.isValid=function(t){return t&&t.bit&&t.ccBits},r.from=function(t,e){if(r.isValid(t))return t;try{return n(t)}catch(t){return e}}},{"./regex":18,"./version-check":21}],14:[function(t,e,r){function n(t){this.mode=o.NUMERIC,this.data=t.toString()}var o=t("./mode");n.getBitsLength=function(t){return 10*Math.floor(t/3)+(t%3?t%3*3+1:0)},n.prototype.getLength=function(){return this.data.length},n.prototype.getBitsLength=function(){return n.getBitsLength(this.data.length)},n.prototype.write=function(t){var e,r,n;for(e=0;e+3<=this.data.length;e+=3)r=this.data.substr(e,3),n=parseInt(r,10),t.put(n,10);var o=this.data.length-e;o>0&&(r=this.data.substr(e),n=parseInt(r,10),t.put(n,3*o+1))},e.exports=n},{"./mode":13}],15:[function(t,e,r){var n=t("../utils/buffer"),o=t("./galois-field");r.mul=function(t,e){var r=new n(t.length+e.length-1);r.fill(0);for(var i=0;i<t.length;i++)for(var a=0;a<e.length;a++)r[i+a]^=o.mul(t[i],e[a]);return r},r.mod=function(t,e){for(var r=new n(t);r.length-e.length>=0;){for(var i=r[0],a=0;a<e.length;a++)r[a]^=o.mul(e[a],i);for(var u=0;u<r.length&&0===r[u];)u++;r=r.slice(u)}return r},r.generateECPolynomial=function(t){for(var e=new n([1]),i=0;i<t;i++)e=r.mul(e,[1,o.exp(i)]);return e}},{"../utils/buffer":27,"./galois-field":10}],16:[function(t,e,r){function n(t,e){for(var r=t.size,n=m.getPositions(e),o=0;o<n.length;o++)for(var i=n[o][0],a=n[o][1],u=-1;u<=7;u++)if(!(i+u<=-1||r<=i+u))for(var s=-1;s<=7;s++)a+s<=-1||r<=a+s||(u>=0&&u<=6&&(0===s||6===s)||s>=0&&s<=6&&(0===u||6===u)||u>=2&&u<=4&&s>=2&&s<=4?t.set(i+u,a+s,!0,!0):t.set(i+u,a+s,!1,!0))}function o(t){for(var e=t.size,r=8;r<e-8;r++){var n=r%2==0;t.set(r,6,n,!0),t.set(6,r,n,!0)}}function i(t,e){for(var r=w.getPositions(e),n=0;n<r.length;n++)for(var o=r[n][0],i=r[n][1],a=-2;a<=2;a++)for(var u=-2;u<=2;u++)-2===a||2===a||-2===u||2===u||0===a&&0===u?t.set(o+a,i+u,!0,!0):t.set(o+a,i+u,!1,!0)}function a(t,e){for(var r,n,o,i=t.size,a=A.getEncodedBits(e),u=0;u<18;u++)r=Math.floor(u/3),n=u%3+i-8-3,o=1==(a>>u&1),t.set(r,n,o,!0),t.set(n,r,o,!0)}function u(t,e,r){var n,o,i=t.size,a=B.getEncodedBits(e,r);for(n=0;n<15;n++)o=1==(a>>n&1),n<6?t.set(n,8,o,!0):n<8?t.set(n+1,8,o,!0):t.set(i-15+n,8,o,!0),n<8?t.set(8,i-n-1,o,!0):n<9?t.set(8,15-n-1+1,o,!0):t.set(8,15-n-1,o,!0);t.set(i-8,8,1,!0)}function s(t,e){for(var r=t.size,n=-1,o=r-1,i=7,a=0,u=r-1;u>0;u-=2)for(6===u&&u--;;){for(var s=0;s<2;s++)if(!t.isReserved(o,u-s)){var f=!1;a<e.length&&(f=1==(e[a]>>>i&1)),t.set(o,u-s,f),i--,-1===i&&(a++,i=7)}if((o+=n)<0||r<=o){o-=n,n=-n;break}}}function f(t,e,r){var n=new p;r.forEach(function(e){n.put(e.mode.bit,4),n.put(e.getLength(),R.getCharCountIndicator(e.mode,t)),e.write(n)});var o=d.getSymbolTotalCodewords(t),i=E.getTotalCodewordsCount(t,e),a=8*(o-i);for(n.getLengthInBits()+4<=a&&n.put(0,4);n.getLengthInBits()%8!=0;)n.putBit(0);for(var u=(a-n.getLengthInBits())/8,s=0;s<u;s++)n.put(s%2?17:236,8);return l(n,t,e)}function l(t,e,r){for(var n=d.getSymbolTotalCodewords(e),o=E.getTotalCodewordsCount(e,r),i=n-o,a=E.getBlocksCount(e,r),u=n%a,s=a-u,f=Math.floor(n/a),l=Math.floor(i/a),c=l+1,g=f-l,p=new b(g),v=0,w=new Array(a),m=new Array(a),y=0,A=new h(t.buffer),B=0;B<a;B++){var R=B<s?l:c;w[B]=A.slice(v,v+R),m[B]=p.encode(w[B]),v+=R,y=Math.max(y,R)}var P,T,C=new h(n),N=0;for(P=0;P<y;P++)for(T=0;T<a;T++)P<w[T].length&&(C[N++]=w[T][P]);for(P=0;P<g;P++)for(T=0;T<a;T++)C[N++]=m[T][P];return C}function c(t,e,r,l){var c;if(T(t))c=P.fromArray(t);else{if("string"!=typeof t)throw new Error("Invalid data");var h=e;if(!h){var g=P.rawSplit(t);h=A.getBestVersionForData(g,r)}c=P.fromString(t,h||40)}var p=A.getBestVersionForData(c,r);if(!p)throw new Error("The amount of data is too big to be stored in a QR Code");if(e){if(e<p)throw new Error("\nThe chosen QR Code version cannot contain this amount of data.\nMinimum version required to store current data is: "+p+".\n")}else e=p;var w=f(e,r,c),m=d.getSymbolSize(e),E=new v(m);return n(E,e),o(E),i(E,e),u(E,r,0),e>=7&&a(E,e),s(E,w),isNaN(l)&&(l=y.getBestMask(E,u.bind(null,E,r))),y.applyMask(l,E),u(E,r,l),{modules:E,version:e,errorCorrectionLevel:r,maskPattern:l,segments:c}}var h=t("../utils/buffer"),d=t("./utils"),g=t("./error-correction-level"),p=t("./bit-buffer"),v=t("./bit-matrix"),w=t("./alignment-pattern"),m=t("./finder-pattern"),y=t("./mask-pattern"),E=t("./error-correction-code"),b=t("./reed-solomon-encoder"),A=t("./version"),B=t("./format-info"),R=t("./mode"),P=t("./segments"),T=t("isarray");r.create=function(t,e){if(void 0===t||""===t)throw new Error("No input text");var r,n,o=g.M;return void 0!==e&&(o=g.from(e.errorCorrectionLevel,g.M),r=A.from(e.version),n=y.from(e.maskPattern),e.toSJISFunc&&d.setToSJISFunction(e.toSJISFunc)),c(t,r,o,n)}},{"../utils/buffer":27,"./alignment-pattern":1,"./bit-buffer":3,"./bit-matrix":4,"./error-correction-code":6,"./error-correction-level":7,"./finder-pattern":8,"./format-info":9,"./mask-pattern":12,"./mode":13,"./reed-solomon-encoder":17,"./segments":19,"./utils":20,"./version":22,isarray:30}],17:[function(t,e,r){function n(t){this.genPoly=void 0,this.degree=t,this.degree&&this.initialize(this.degree)}var o=t("../utils/buffer"),i=t("./polynomial");n.prototype.initialize=function(t){this.degree=t,this.genPoly=i.generateECPolynomial(this.degree)},n.prototype.encode=function(t){if(!this.genPoly)throw new Error("Encoder not initialized");var e=new o(this.degree);e.fill(0);var r=o.concat([t,e],t.length+this.degree),n=i.mod(r,this.genPoly),a=this.degree-n.length;if(a>0){var u=new o(this.degree);return u.fill(0),n.copy(u,a),u}return n},e.exports=n},{"../utils/buffer":27,"./polynomial":15}],18:[function(t,e,r){var n="(?:[u3000-u303F]|[u3040-u309F]|[u30A0-u30FF]|[uFF00-uFFEF]|[u4E00-u9FAF]|[u2605-u2606]|[u2190-u2195]|u203B|[u2010u2015u2018u2019u2025u2026u201Cu201Du2225u2260]|[u0391-u0451]|[u00A7u00A8u00B1u00B4u00D7u00F7])+";n=n.replace(/u/g,"\\u");var o="(?:(?![A-Z0-9 $%*+\\-./:]|"+n+").)+";r.KANJI=new RegExp(n,"g"),r.BYTE_KANJI=new RegExp("[^A-Z0-9 $%*+\\-./:]+","g"),r.BYTE=new RegExp(o,"g"),r.NUMERIC=new RegExp("[0-9]+","g"),r.ALPHANUMERIC=new RegExp("[A-Z $%*+\\-./:]+","g");var i=new RegExp("^"+n+"$"),a=new RegExp("^[0-9]+$"),u=new RegExp("^[A-Z0-9 $%*+\\-./:]+$");r.testKanji=function(t){return i.test(t)},r.testNumeric=function(t){return a.test(t)},r.testAlphanumeric=function(t){return u.test(t)}},{}],19:[function(t,e,r){function n(t){return unescape(encodeURIComponent(t)).length}function o(t,e,r){for(var n,o=[];null!==(n=t.exec(r));)o.push({data:n[0],index:n.index,mode:e,length:n[0].length});return o}function i(t){var e,r,n=o(v.NUMERIC,c.NUMERIC,t),i=o(v.ALPHANUMERIC,c.ALPHANUMERIC,t);return w.isKanjiModeEnabled()?(e=o(v.BYTE,c.BYTE,t),r=o(v.KANJI,c.KANJI,t)):(e=o(v.BYTE_KANJI,c.BYTE,t),r=[]),n.concat(i,e,r).sort(function(t,e){return t.index-e.index}).map(function(t){return{data:t.data,mode:t.mode,length:t.length}})}function a(t,e){switch(e){case c.NUMERIC:return h.getBitsLength(t);case c.ALPHANUMERIC:return d.getBitsLength(t);case c.KANJI:return p.getBitsLength(t);case c.BYTE:return g.getBitsLength(t)}}function u(t){return t.reduce(function(t,e){var r=t.length-1>=0?t[t.length-1]:null;return r&&r.mode===e.mode?(t[t.length-1].data+=e.data,t):(t.push(e),t)},[])}function s(t){for(var e=[],r=0;r<t.length;r++){var o=t[r];switch(o.mode){case c.NUMERIC:e.push([o,{data:o.data,mode:c.ALPHANUMERIC,length:o.length},{data:o.data,mode:c.BYTE,length:o.length}]);break;case c.ALPHANUMERIC:e.push([o,{data:o.data,mode:c.BYTE,length:o.length}]);break;case c.KANJI:e.push([o,{data:o.data,mode:c.BYTE,length:n(o.data)}]);break;case c.BYTE:e.push([{data:o.data,mode:c.BYTE,length:n(o.data)}])}}return e}function f(t,e){for(var r={},n={start:{}},o=["start"],i=0;i<t.length;i++){for(var u=t[i],s=[],f=0;f<u.length;f++){var l=u[f],h=""+i+f;s.push(h),r[h]={node:l,lastCount:0},n[h]={};for(var d=0;d<o.length;d++){var g=o[d];r[g]&&r[g].node.mode===l.mode?(n[g][h]=a(r[g].lastCount+l.length,l.mode)-a(r[g].lastCount,l.mode),r[g].lastCount+=l.length):(r[g]&&(r[g].lastCount=l.length),n[g][h]=a(l.length,l.mode)+4+c.getCharCountIndicator(l.mode,e))}}o=s}for(d=0;d<o.length;d++)n[o[d]].end=0;return{map:n,table:r}}function l(t,e){var r,n=c.getBestModeForData(t);if((r=c.from(e,n))!==c.BYTE&&r.bit<n.bit)throw new Error('"'+t+'" cannot be encoded with mode '+c.toString(r)+".\n Suggested mode is: "+c.toString(n));switch(r!==c.KANJI||w.isKanjiModeEnabled()||(r=c.BYTE),r){case c.NUMERIC:return new h(t);case c.ALPHANUMERIC:return new d(t);case c.KANJI:return new p(t);case c.BYTE:return new g(t)}}var c=t("./mode"),h=t("./numeric-data"),d=t("./alphanumeric-data"),g=t("./byte-data"),p=t("./kanji-data"),v=t("./regex"),w=t("./utils"),m=t("dijkstrajs");r.fromArray=function(t){return t.reduce(function(t,e){return"string"==typeof e?t.push(l(e,null)):e.data&&t.push(l(e.data,e.mode)),t},[])},r.fromString=function(t,e){for(var n=i(t,w.isKanjiModeEnabled()),o=s(n),a=f(o,e),l=m.find_path(a.map,"start","end"),c=[],h=1;h<l.length-1;h++)c.push(a.table[l[h]].node);return r.fromArray(u(c))},r.rawSplit=function(t){return r.fromArray(i(t,w.isKanjiModeEnabled()))}},{"./alphanumeric-data":2,"./byte-data":5,"./kanji-data":11,"./mode":13,"./numeric-data":14,"./regex":18,"./utils":20,dijkstrajs:29}],20:[function(t,e,r){var n,o=[0,26,44,70,100,134,172,196,242,292,346,404,466,532,581,655,733,815,901,991,1085,1156,1258,1364,1474,1588,1706,1828,1921,2051,2185,2323,2465,2611,2761,2876,3034,3196,3362,3532,3706];r.getSymbolSize=function(t){if(!t)throw new Error('"version" cannot be null or undefined');if(t<1||t>40)throw new Error('"version" should be in range from 1 to 40');return 4*t+17},r.getSymbolTotalCodewords=function(t){return o[t]},r.getBCHDigit=function(t){for(var e=0;0!==t;)e++,t>>>=1;return e},r.setToSJISFunction=function(t){if("function"!=typeof t)throw new Error('"toSJISFunc" is not a valid function.');n=t},r.isKanjiModeEnabled=function(){return void 0!==n},r.toSJIS=function(t){return n(t)}},{}],21:[function(t,e,r){r.isValid=function(t){return!isNaN(t)&&t>=1&&t<=40}},{}],22:[function(t,e,r){function n(t,e,n){for(var o=1;o<=40;o++)if(e<=r.getCapacity(o,n,t))return o}function o(t,e){return l.getCharCountIndicator(t,e)+4}function i(t,e){var r=0;return t.forEach(function(t){var n=o(t.mode,e);r+=n+t.getBitsLength()}),r}function a(t,e){for(var n=1;n<=40;n++){if(i(t,n)<=r.getCapacity(n,e,l.MIXED))return n}}var u=t("./utils"),s=t("./error-correction-code"),f=t("./error-correction-level"),l=t("./mode"),c=t("./version-check"),h=t("isarray"),d=u.getBCHDigit(7973);r.from=function(t,e){return c.isValid(t)?parseInt(t,10):e},r.getCapacity=function(t,e,r){if(!c.isValid(t))throw new Error("Invalid QR Code version");void 0===r&&(r=l.BYTE);var n=u.getSymbolTotalCodewords(t),i=s.getTotalCodewordsCount(t,e),a=8*(n-i);if(r===l.MIXED)return a;var f=a-o(r,t);switch(r){case l.NUMERIC:return Math.floor(f/10*3);case l.ALPHANUMERIC:return Math.floor(f/11*2);case l.KANJI:return Math.floor(f/13);case l.BYTE:default:return Math.floor(f/8)}},r.getBestVersionForData=function(t,e){var r,o=f.from(e,f.M);if(h(t)){if(t.length>1)return a(t,o);if(0===t.length)return 1;r=t[0]}else r=t;return n(r.mode,r.getLength(),o)},r.getEncodedBits=function(t){if(!c.isValid(t)||t<7)throw new Error("Invalid QR Code version");for(var e=t<<12;u.getBCHDigit(e)-d>=0;)e^=7973<<u.getBCHDigit(e)-d;return t<<12|e}},{"./error-correction-code":6,"./error-correction-level":7,"./mode":13,"./utils":20,"./version-check":21,isarray:30}],23:[function(t,e,r){function n(t,e,r,n,a){var u=[].slice.call(arguments,1),s=u.length,f="function"==typeof u[s-1];if(!f&&!o())throw new Error("Callback required as last argument");if(!f){if(s<1)throw new Error("Too few arguments provided");return 1===s?(r=e,e=n=void 0):2!==s||e.getContext||(n=r,r=e,e=void 0),new Promise(function(o,a){try{var u=i.create(r,n);o(t(u,e,n))}catch(t){a(t)}})}if(s<2)throw new Error("Too few arguments provided");2===s?(a=r,r=e,e=n=void 0):3===s&&(e.getContext&&void 0===a?(a=n,n=void 0):(a=n,n=r,r=e,e=void 0));try{var l=i.create(r,n);a(null,t(l,e,n))}catch(t){a(t)}}var o=t("can-promise"),i=t("./core/qrcode"),a=t("./renderer/canvas"),u=t("./renderer/svg-tag.js");r.create=i.create,r.toCanvas=n.bind(null,a.render),r.toDataURL=n.bind(null,a.renderToDataURL),r.toString=n.bind(null,function(t,e,r){return u.render(t,r)})},{"./core/qrcode":16,"./renderer/canvas":24,"./renderer/svg-tag.js":25,"can-promise":28}],24:[function(t,e,r){function n(t,e,r){t.clearRect(0,0,e.width,e.height),e.style||(e.style={}),e.height=r,e.width=r,e.style.height=r+"px",e.style.width=r+"px"}function o(){try{return document.createElement("canvas")}catch(t){throw new Error("You need to specify a canvas element")}}var i=t("./utils");r.render=function(t,e,r){var a=r,u=e;void 0!==a||e&&e.getContext||(a=e,e=void 0),e||(u=o()),a=i.getOptions(a);var s=i.getImageWidth(t.modules.size,a),f=u.getContext("2d"),l=f.createImageData(s,s);return i.qrToImageData(l.data,t,a),n(f,u,s),f.putImageData(l,0,0),u},r.renderToDataURL=function(t,e,n){var o=n;void 0!==o||e&&e.getContext||(o=e,e=void 0),o||(o={});var i=r.render(t,e,o),a=o.type||"image/png",u=o.rendererOpts||{};return i.toDataURL(a,u.quality)}},{"./utils":26}],25:[function(t,e,r){function n(t,e){var r=t.a/255,n=e+'="'+t.hex+'"';return r<1?n+" "+e+'-opacity="'+r.toFixed(2).slice(1)+'"':n}function o(t,e,r){var n=t+e;return void 0!==r&&(n+=" "+r),n}function i(t,e,r){for(var n="",i=0,a=!1,u=0,s=0;s<t.length;s++){var f=Math.floor(s%e),l=Math.floor(s/e);f||a||(a=!0),t[s]?(u++,s>0&&f>0&&t[s-1]||(n+=a?o("M",f+r,.5+l+r):o("m",i,0),i=0,a=!1),f+1<e&&t[s+1]||(n+=o("h",u),u=0)):i++}return n}var a=t("./utils");r.render=function(t,e,r){var o=a.getOptions(e),u=t.modules.size,s=t.modules.data,f=u+2*o.margin,l=o.color.light.a?"<path "+n(o.color.light,"fill")+' d="M0 0h'+f+"v"+f+'H0z"/>':"",c="<path "+n(o.color.dark,"stroke")+' d="'+i(s,u,o.margin)+'"/>',h='viewBox="0 0 '+f+" "+f+'"',d=o.width?'width="'+o.width+'" height="'+o.width+'" ':"",g='<svg xmlns="http://www.w3.org/2000/svg" '+d+h+' shape-rendering="crispEdges">'+l+c+"</svg>";return"function"==typeof r&&r(null,g),g}},{"./utils":26}],26:[function(t,e,r){function n(t){if("string"!=typeof t)throw new Error("Color should be defined as hex string");var e=t.slice().replace("#","").split("");if(e.length<3||5===e.length||e.length>8)throw new Error("Invalid hex color: "+t);3!==e.length&&4!==e.length||(e=Array.prototype.concat.apply([],e.map(function(t){return[t,t]}))),6===e.length&&e.push("F","F");var r=parseInt(e.join(""),16);return{r:r>>24&255,g:r>>16&255,b:r>>8&255,a:255&r,hex:"#"+e.slice(0,6).join("")}}r.getOptions=function(t){t||(t={}),t.color||(t.color={});var e=void 0===t.margin||null===t.margin||t.margin<0?4:t.margin,r=t.width&&t.width>=21?t.width:void 0,o=t.scale||4;return{width:r,scale:r?4:o,margin:e,color:{dark:n(t.color.dark||"#000000ff"),light:n(t.color.light||"#ffffffff")},type:t.type,rendererOpts:t.rendererOpts||{}}},r.getScale=function(t,e){return e.width&&e.width>=t+2*e.margin?e.width/(t+2*e.margin):e.scale},r.getImageWidth=function(t,e){var n=r.getScale(t,e);return Math.floor((t+2*e.margin)*n)},r.qrToImageData=function(t,e,n){for(var o=e.modules.size,i=e.modules.data,a=r.getScale(o,n),u=Math.floor((o+2*n.margin)*a),s=n.margin*a,f=[n.color.light,n.color.dark],l=0;l<u;l++)for(var c=0;c<u;c++){var h=4*(l*u+c),d=n.color.light;if(l>=s&&c>=s&&l<u-s&&c<u-s){var g=Math.floor((l-s)/a),p=Math.floor((c-s)/a);d=f[i[g*o+p]?1:0]}t[h++]=d.r,t[h++]=d.g,t[h++]=d.b,t[h]=d.a}}},{}],27:[function(t,e,r){"use strict";function n(t,e,r){return n.TYPED_ARRAY_SUPPORT||this instanceof n?"number"==typeof t?u(this,t):v(this,t,e,r):new n(t,e,r)}function o(t){if(t>=m)throw new RangeError("Attempt to allocate Buffer larger than maximum size: 0x"+m.toString(16)+" bytes");return 0|t}function i(t){return t!==t}function a(t,e){var r;return n.TYPED_ARRAY_SUPPORT?(r=new Uint8Array(e),r.__proto__=n.prototype):(r=t,null===r&&(r=new n(e)),r.length=e),r}function u(t,e){var r=a(t,e<0?0:0|o(e));if(!n.TYPED_ARRAY_SUPPORT)for(var i=0;i<e;++i)r[i]=0;return r}function s(t,e){var r=0|d(e),n=a(t,r),o=n.write(e);return o!==r&&(n=n.slice(0,o)),n}function f(t,e){for(var r=e.length<0?0:0|o(e.length),n=a(t,r),i=0;i<r;i+=1)n[i]=255&e[i];return n}function l(t,e,r,o){if(r<0||e.byteLength<r)throw new RangeError("'offset' is out of bounds");if(e.byteLength<r+(o||0))throw new RangeError("'length' is out of bounds");var i;return i=void 0===r&&void 0===o?new Uint8Array(e):void 0===o?new Uint8Array(e,r):new Uint8Array(e,r,o),n.TYPED_ARRAY_SUPPORT?i.__proto__=n.prototype:i=f(t,i),i}function c(t,e){if(n.isBuffer(e)){var r=0|o(e.length),u=a(t,r);return 0===u.length?u:(e.copy(u,0,0,r),u)}if(e){if("undefined"!=typeof ArrayBuffer&&e.buffer instanceof ArrayBuffer||"length"in e)return"number"!=typeof e.length||i(e.length)?a(t,0):f(t,e);if("Buffer"===e.type&&Array.isArray(e.data))return f(t,e.data)}throw new TypeError("First argument must be a string, Buffer, ArrayBuffer, Array, or array-like object.")}function h(t,e){e=e||1/0;for(var r,n=t.length,o=null,i=[],a=0;a<n;++a){if((r=t.charCodeAt(a))>55295&&r<57344){if(!o){if(r>56319){(e-=3)>-1&&i.push(239,191,189);continue}if(a+1===n){(e-=3)>-1&&i.push(239,191,189);continue}o=r;continue}if(r<56320){(e-=3)>-1&&i.push(239,191,189),o=r;continue}r=65536+(o-55296<<10|r-56320)}else o&&(e-=3)>-1&&i.push(239,191,189);if(o=null,r<128){if((e-=1)<0)break;i.push(r)}else if(r<2048){if((e-=2)<0)break;i.push(r>>6|192,63&r|128)}else if(r<65536){if((e-=3)<0)break;i.push(r>>12|224,r>>6&63|128,63&r|128)}else{if(!(r<1114112))throw new Error("Invalid code point");if((e-=4)<0)break;i.push(r>>18|240,r>>12&63|128,r>>6&63|128,63&r|128)}}return i}function d(t){return n.isBuffer(t)?t.length:"undefined"!=typeof ArrayBuffer&&"function"==typeof ArrayBuffer.isView&&(ArrayBuffer.isView(t)||t instanceof ArrayBuffer)?t.byteLength:("string"!=typeof t&&(t=""+t),0===t.length?0:h(t).length)}function g(t,e,r,n){for(var o=0;o<n&&!(o+r>=e.length||o>=t.length);++o)e[o+r]=t[o];return o}function p(t,e,r,n){return g(h(e,t.length-r),t,r,n)}function v(t,e,r,n){if("number"==typeof e)throw new TypeError('"value" argument must not be a number');return"undefined"!=typeof ArrayBuffer&&e instanceof ArrayBuffer?l(t,e,r,n):"string"==typeof e?s(t,e,r):c(t,e)}var w=t("isarray");n.TYPED_ARRAY_SUPPORT=function(){try{var t=new Uint8Array(1);return t.__proto__={__proto__:Uint8Array.prototype,foo:function(){return 42}},42===t.foo()}catch(t){return!1}}();var m=n.TYPED_ARRAY_SUPPORT?2147483647:1073741823;n.TYPED_ARRAY_SUPPORT&&(n.prototype.__proto__=Uint8Array.prototype,n.__proto__=Uint8Array,"undefined"!=typeof Symbol&&Symbol.species&&n[Symbol.species]===n&&Object.defineProperty(n,Symbol.species,{value:null,configurable:!0,enumerable:!1,writable:!1})),n.prototype.write=function(t,e,r){void 0===e?(r=this.length,e=0):void 0===r&&"string"==typeof e?(r=this.length,e=0):isFinite(e)&&(e|=0,isFinite(r)?r|=0:r=void 0);var n=this.length-e;if((void 0===r||r>n)&&(r=n),t.length>0&&(r<0||e<0)||e>this.length)throw new RangeError("Attempt to write outside buffer bounds");return p(this,t,e,r)},n.prototype.slice=function(t,e){var r=this.length;t=~~t,e=void 0===e?r:~~e,t<0?(t+=r)<0&&(t=0):t>r&&(t=r),e<0?(e+=r)<0&&(e=0):e>r&&(e=r),e<t&&(e=t);var o;if(n.TYPED_ARRAY_SUPPORT)o=this.subarray(t,e),o.__proto__=n.prototype;else{var i=e-t;o=new n(i,void 0);for(var a=0;a<i;++a)o[a]=this[a+t]}return o},n.prototype.copy=function(t,e,r,o){if(r||(r=0),o||0===o||(o=this.length),e>=t.length&&(e=t.length),e||(e=0),o>0&&o<r&&(o=r),o===r)return 0;if(0===t.length||0===this.length)return 0;if(e<0)throw new RangeError("targetStart out of bounds");if(r<0||r>=this.length)throw new RangeError("sourceStart out of bounds");if(o<0)throw new RangeError("sourceEnd out of bounds");o>this.length&&(o=this.length),t.length-e<o-r&&(o=t.length-e+r);var i,a=o-r;if(this===t&&r<e&&e<o)for(i=a-1;i>=0;--i)t[i+e]=this[i+r];else if(a<1e3||!n.TYPED_ARRAY_SUPPORT)for(i=0;i<a;++i)t[i+e]=this[i+r];else Uint8Array.prototype.set.call(t,this.subarray(r,r+a),e);return a},n.prototype.fill=function(t,e,r){if("string"==typeof t){if("string"==typeof e?(e=0,r=this.length):"string"==typeof r&&(r=this.length),1===t.length){var o=t.charCodeAt(0);o<256&&(t=o)}}else"number"==typeof t&&(t&=255);if(e<0||this.length<e||this.length<r)throw new RangeError("Out of range index");if(r<=e)return this;e>>>=0,r=void 0===r?this.length:r>>>0,t||(t=0);var i;if("number"==typeof t)for(i=e;i<r;++i)this[i]=t;else{var a=n.isBuffer(t)?t:new n(t),u=a.length;for(i=0;i<r-e;++i)this[i+e]=a[i%u]}return this},n.concat=function(t,e){if(!w(t))throw new TypeError('"list" argument must be an Array of Buffers');if(0===t.length)return a(null,0);var r;if(void 0===e)for(e=0,r=0;r<t.length;++r)e+=t[r].length;var o=u(null,e),i=0;for(r=0;r<t.length;++r){var s=t[r];if(!n.isBuffer(s))throw new TypeError('"list" argument must be an Array of Buffers');s.copy(o,i),i+=s.length}return o},n.byteLength=d,n.prototype._isBuffer=!0,n.isBuffer=function(t){return!(null==t||!t._isBuffer)},e.exports=n},{isarray:30}],28:[function(t,e,r){"use strict";var n=t("window-or-global");e.exports=function(){return"function"==typeof n.Promise&&"function"==typeof n.Promise.prototype.then}},{"window-or-global":31}],29:[function(t,e,r){"use strict";var n={single_source_shortest_paths:function(t,e,r){var o={},i={};i[e]=0;var a=n.PriorityQueue.make();a.push(e,0);for(var u,s,f,l,c,h,d,g;!a.empty();){u=a.pop(),s=u.value,l=u.cost,c=t[s]||{};for(f in c)c.hasOwnProperty(f)&&(h=c[f],d=l+h,g=i[f],(void 0===i[f]||g>d)&&(i[f]=d,a.push(f,d),o[f]=s))}if(void 0!==r&&void 0===i[r]){var p=["Could not find a path from ",e," to ",r,"."].join("");throw new Error(p)}return o},extract_shortest_path_from_predecessor_list:function(t,e){for(var r=[],n=e;n;)r.push(n),t[n],n=t[n];return r.reverse(),r},find_path:function(t,e,r){var o=n.single_source_shortest_paths(t,e,r);return n.extract_shortest_path_from_predecessor_list(o,r)},PriorityQueue:{make:function(t){var e,r=n.PriorityQueue,o={};t=t||{};for(e in r)r.hasOwnProperty(e)&&(o[e]=r[e]);return o.queue=[],o.sorter=t.sorter||r.default_sorter,o},default_sorter:function(t,e){return t.cost-e.cost},push:function(t,e){var r={value:t,cost:e};this.queue.push(r),this.queue.sort(this.sorter)},pop:function(){return this.queue.shift()},empty:function(){return 0===this.queue.length}}};void 0!==e&&(e.exports=n)},{}],30:[function(t,e,r){var n={}.toString;e.exports=Array.isArray||function(t){return"[object Array]"==n.call(t)}},{}],31:[function(t,e,r){
(function(t){"use strict";e.exports="object"==typeof self&&self.self===self&&self||"object"==typeof t&&t.global===t&&t||this}).call(this,"undefined"!=typeof global?global:"undefined"!=typeof self?self:"undefined"!=typeof window?window:{})},{}]},{},[23])(23)});
//# sourceMappingURL=qrcode.min.js.map</script>
    <!-- SHA3 library for Light Wallet.
         NOTE: pinned to the package's pre-built /build/ asset (NOT /src/, which jsDelivr
         minifies on-the-fly and explicitly marks "Do NOT use SRI"). SRI hash is over the
         exact pinned bytes of js-sha3@0.9.3/build/sha3.min.js. -->
    <script src="https://cdn.jsdelivr.net/npm/js-sha3@0.9.3/build/sha3.min.js"
            integrity="sha384-+JAeTqUiH9WuByObPHouP4rQKYUTLQ9AQW4HHJZ4uNmkA2+nkDpbssQNGsVXnJpe"
            crossorigin="anonymous"></script>
    <!-- Ethers.js for MetaMask / Base bridge integration (pre-built /dist/ → SRI-safe) -->
    <script src="https://cdn.jsdelivr.net/npm/ethers@5.7.2/dist/ethers.umd.min.js"
            integrity="sha384-Htz1SE4Sl5aitpvFgr2j0sfsGUIuSXI6t8hEyrlQ93zflEF3a29bH2AvkUROUw7J"
            crossorigin="anonymous"></script>
    <!-- Dilithium WASM Module (must load before dilithium-crypto.js) -->
    <script src="js/dilithium.js"></script>
    <!-- Light Wallet Modules -->
    <script src="js/dilithium-crypto.js"></script>
    <script src="js/connection-manager.js"></script>
    <script src="js/local-wallet.js"></script>
    <script src="js/transaction-builder.js"></script>
    <style>
        :root {
            --primary: #C8A24E;
            --primary-dark: #B08A3E;
            --secondary: #E8C860;
            --accent: #C8A24E;
            --bg-dark: #0F0F0D;
            --bg-darker: #0A0A09;
            --bg-card: #161614;
            --bg-card-hover: #1E1E1A;
            --text-primary: #F5F0E8;
            --text-secondary: #8A8A80;
            --text-muted: #5A5A52;
            --border: #1F1F1C;
            --success: #22c55e;
            --warning: #f59e0b;
            --error: #ef4444;
            --sidebar-width: 240px;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-darker);
            color: var(--text-primary);
            min-height: 100vh;
            display: flex;
        }

        /* Sidebar */
        .sidebar {
            width: var(--sidebar-width);
            background: var(--bg-dark);
            border-right: 1px solid var(--border);
            padding: 20px 0;
            display: flex;
            flex-direction: column;
            position: fixed;
            height: 100vh;
            overflow-y: auto;
        }

        .logo {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 0 20px 24px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 20px;
        }

        .logo img {
            width: 40px;
            height: 40px;
        }

        .logo-text {
            font-size: 1.25rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .nav-section {
            margin-bottom: 24px;
        }

        .nav-section-title {
            font-size: 0.75rem;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            padding: 0 20px;
            margin-bottom: 8px;
        }

        .nav-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px 20px;
            color: var(--text-secondary);
            cursor: pointer;
            transition: all 0.2s;
            border-left: 3px solid transparent;
        }

        .nav-item:hover {
            background: var(--bg-card);
            color: var(--text-primary);
        }

        .nav-item.active {
            background: rgba(200, 162, 78, 0.1);
            color: var(--primary);
            border-left-color: var(--primary);
        }

        .nav-item svg {
            width: 20px;
            height: 20px;
        }

        .connection-status {
            margin-top: auto;
            padding: 16px 20px;
            border-top: 1px solid var(--border);
        }

        .status-indicator {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 0.875rem;
        }

        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--error);
        }

        .status-dot.connected {
            background: var(--success);
        }

        /* Main Content */
        .main-content {
            flex: 1;
            margin-left: var(--sidebar-width);
            padding: 32px;
            min-height: 100vh;
        }

        .page {
            display: none;
        }

        .page.active {
            display: block;
        }

        .page-header {
            margin-bottom: 32px;
        }

        .page-title {
            font-family: 'DM Serif Display', serif;
            font-size: 1.75rem;
            font-weight: 400;
            margin-bottom: 8px;
        }

        .page-subtitle {
            color: var(--text-secondary);
        }

        h1, h2, h3 {
            font-family: 'DM Serif Display', serif;
            font-weight: 400;
        }

        /* Cards */
        .card {
            background: var(--bg-card);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
            border: 1px solid var(--border);
        }

        .card-title {
            font-size: 0.875rem;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 16px;
        }

        /* Balance Display */
        .balance-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 32px;
        }

        .balance-card {
            background: var(--bg-card);
            border-radius: 12px;
            padding: 24px;
            border: 1px solid var(--border);
        }

        .balance-card.total {
            background: linear-gradient(135deg, rgba(200, 162, 78, 0.2), rgba(232, 200, 96, 0.2));
            border-color: rgba(200, 162, 78, 0.3);
        }

        .balance-label {
            font-size: 0.875rem;
            color: var(--text-muted);
            margin-bottom: 8px;
        }

        .balance-amount {
            font-size: clamp(1rem, 3.5vw, 2rem);
            font-weight: 700;
            font-family: 'JetBrains Mono', monospace;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .balance-unit {
            font-size: 1rem;
            color: var(--text-secondary);
            margin-left: 8px;
        }

        /* Blockchain Info */
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
        }

        .info-item {
            display: flex;
            flex-direction: column;
            gap: 4px;
        }

        .info-label {
            font-size: 0.75rem;
            color: var(--text-muted);
            text-transform: uppercase;
        }

        .info-value {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9rem;
            word-break: break-all;
            overflow-wrap: break-word;
        }

        /* Forms */
        .form-group {
            margin-bottom: 20px;
        }

        .form-label {
            display: block;
            font-size: 0.875rem;
            font-weight: 500;
            color: var(--text-secondary);
            margin-bottom: 8px;
        }

        .form-input {
            width: 100%;
            padding: 12px 16px;
            background: var(--bg-darker);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--text-primary);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9rem;
            transition: all 0.2s;
        }

        .form-input:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(200, 162, 78, 0.2);
        }

        .form-input::placeholder {
            color: var(--text-muted);
        }

        .form-hint {
            font-size: 0.75rem;
            color: var(--text-muted);
            margin-top: 6px;
        }

        /* Buttons */
        .btn {
            padding: 12px 24px;
            border-radius: 8px;
            font-weight: 600;
            font-size: 0.9rem;
            cursor: pointer;
            transition: all 0.2s;
            border: none;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }

        .btn-primary {
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            color: white;
        }

        .btn-primary:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(200, 162, 78, 0.4);
        }

        .btn-primary:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none;
        }

        .btn-secondary {
            background: var(--bg-card);
            color: var(--text-primary);
            border: 1px solid var(--border);
        }

        .btn-secondary:hover {
            background: var(--bg-card-hover);
        }

        /* Address Display */
        .address-display {
            display: flex;
            align-items: center;
            gap: 12px;
            background: var(--bg-darker);
            padding: 16px;
            border-radius: 8px;
            border: 1px solid var(--border);
            margin-bottom: 20px;
        }

        .address-text {
            flex: 1;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            word-break: break-all;
        }

        .copy-btn {
            padding: 8px 12px;
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 6px;
            color: var(--text-secondary);
            cursor: pointer;
            transition: all 0.2s;
        }

        .copy-btn:hover {
            background: var(--bg-card-hover);
            color: var(--text-primary);
        }

        .copy-btn.copied {
            background: var(--success);
            color: white;
            border-color: var(--success);
        }

        /* QR Code */
        .qr-container {
            display: flex;
            justify-content: center;
            padding: 24px;
            background: white;
            border-radius: 12px;
            margin: 20px 0;
        }

        #qrcode {
            width: 200px;
            height: 200px;
        }

        /* Transaction List */
        .tx-list {
            border: 1px solid var(--border);
            border-radius: 8px;
            overflow: hidden;
        }

        .tx-item {
            display: flex;
            align-items: center;
            padding: 16px;
            border-bottom: 1px solid var(--border);
            transition: background 0.2s;
        }

        .tx-item:last-child {
            border-bottom: none;
        }

        .tx-item:hover {
            background: var(--bg-card-hover);
        }

        .tx-icon {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-right: 16px;
        }

        .tx-icon.received {
            background: rgba(34, 197, 94, 0.2);
            color: var(--success);
        }

        .tx-icon.sent {
            background: rgba(239, 68, 68, 0.2);
            color: var(--error);
        }

        .tx-icon.spent {
            background: rgba(100, 116, 139, 0.2);
            color: var(--text-muted);
        }

        .tx-icon.mining {
            background: rgba(234, 179, 8, 0.2);
            color: #f59e0b;
        }

        .tx-details {
            flex: 1;
        }

        .tx-type {
            font-weight: 600;
            margin-bottom: 4px;
        }

        .tx-hash {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            color: var(--text-muted);
        }

        .tx-amount {
            text-align: right;
            font-family: 'JetBrains Mono', monospace;
            font-weight: 600;
        }

        .tx-amount.positive {
            color: var(--success);
        }

        .tx-amount.negative {
            color: var(--error);
        }

        .tx-confirmations {
            font-size: 0.75rem;
            color: var(--text-muted);
        }

        /* Alerts */
        .alert {
            padding: 16px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: flex;
            align-items: flex-start;
            gap: 12px;
        }

        .alert-error {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            color: var(--error);
        }

        .alert-success {
            background: rgba(34, 197, 94, 0.1);
            border: 1px solid rgba(34, 197, 94, 0.3);
            color: var(--success);
        }

        .alert-warning {
            background: rgba(245, 158, 11, 0.1);
            border: 1px solid rgba(245, 158, 11, 0.3);
            color: var(--warning);
        }

        /* Loading */
        .loading {
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 40px;
            color: var(--text-muted);
        }

        .spinner {
            width: 24px;
            height: 24px;
            border: 3px solid var(--border);
            border-top-color: var(--primary);
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin-right: 12px;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        /* Empty State */
        .empty-state {
            text-align: center;
            padding: 48px;
            color: var(--text-muted);
        }

        .empty-state svg {
            width: 64px;
            height: 64px;
            margin-bottom: 16px;
            opacity: 0.5;
        }

        /* Responsive */
        /* Mobile bottom navigation */
        .mobile-nav {
            display: none;
        }
        .mobile-more-overlay {
            display: none;
        }

        @media (max-width: 768px) {
            /* Hide sidebar on mobile */
            .sidebar {
                display: none !important;
            }

            /* Full-width main content */
            .main-content {
                margin-left: 0 !important;
                padding: 16px !important;
                padding-bottom: 80px !important; /* space for bottom nav */
            }

            /* Show bottom navigation */
            .mobile-nav {
                display: flex;
                position: fixed;
                bottom: 0;
                left: 0;
                right: 0;
                height: 64px;
                background: var(--bg-dark);
                border-top: 1px solid var(--border);
                z-index: 1000;
                justify-content: space-around;
                align-items: center;
                padding: 0 4px;
            }
            .mobile-nav-item {
                display: flex;
                flex-direction: column;
                align-items: center;
                gap: 3px;
                padding: 8px 4px;
                color: var(--text-muted);
                cursor: pointer;
                min-width: 52px;
                -webkit-tap-highlight-color: transparent;
            }
            .mobile-nav-item.active { color: var(--primary); }
            .mobile-nav-item svg { width: 22px; height: 22px; }
            .mobile-nav-item span { font-size: 10px; font-weight: 500; }

            /* More menu overlay */
            .mobile-more-overlay {
                position: fixed;
                top: 0; left: 0; right: 0; bottom: 0;
                background: rgba(0,0,0,0.6);
                z-index: 1001;
            }
            .mobile-more-overlay.active { display: flex !important; align-items: flex-end; }
            .mobile-more-sheet {
                width: 100%;
                background: var(--bg-card);
                border-top: 1px solid var(--border);
                border-radius: 16px 16px 0 0;
                padding: 20px 24px;
                padding-bottom: 80px; /* clear bottom nav */
            }
            .mobile-more-item {
                padding: 14px 0;
                font-size: 1rem;
                color: var(--text-primary);
                cursor: pointer;
                border-bottom: 1px solid var(--border);
            }
            .mobile-more-item:last-of-type { border-bottom: none; }

            /* Balance cards */
            .balance-amount {
                font-size: clamp(1.1rem, 5vw, 1.8rem);
            }
            .balance-grid {
                gap: 12px !important;
            }
            .balance-card {
                padding: 16px !important;
            }

            /* Page headers */
            .page-header {
                margin-bottom: 16px !important;
            }
            .page-title {
                font-size: 1.4rem !important;
            }

            /* Cards */
            .card {
                padding: 16px !important;
                margin-bottom: 12px !important;
            }
            .card-title {
                font-size: 0.95rem !important;
            }

            /* Hide mining on mobile (requires a node) */
            .mining-only {
                display: none !important;
            }

            /* Show chain toggle on mobile dashboard */
            .mobile-chain-toggle {
                display: block !important;
            }

            /* Dashboard quick actions full width */
            .cards-row {
                grid-template-columns: 1fr !important;
            }

            /* Bridge sub-tabs */
            .bridge-tab {
                font-size: 0.8rem !important;
                padding: 8px 4px !important;
            }

            /* Form inputs - ensure full width */
            .form-input, .form-group input, .form-group select, .form-group textarea {
                font-size: 16px !important; /* prevents iOS zoom */
            }

            /* Transaction list */
            .tx-item {
                padding: 10px 0 !important;
            }

            /* Welcome flow */
            #welcomeMnemonicWords {
                grid-template-columns: repeat(2, 1fr) !important;
            }

            /* PWA install banner clearance */
            #pwaInstallBanner {
                bottom: 64px !important;
            }
        }

        /* Small phones */
        @media (max-width: 480px) {
            .main-content {
                padding: 12px !important;
                padding-bottom: 76px !important;
            }

            .balance-amount {
                font-size: clamp(0.9rem, 4.5vw, 1.4rem);
            }

            .balance-grid {
                grid-template-columns: 1fr !important;
                gap: 8px !important;
            }

            .page-title {
                font-size: 1.2rem !important;
            }

            .btn {
                padding: 10px 16px !important;
                font-size: 0.85rem !important;
            }

            /* Stack bridge chain toggles */
            .bridge-chain-opt, .bridge-wchain-opt {
                font-size: 0.75rem !important;
                padding: 6px 2px !important;
            }

            /* Tighter cards */
            .card {
                padding: 12px !important;
            }
        }
    </style>
</head>
<body>
    <!-- Sidebar -->
    <nav class="sidebar">
        <div class="logo">
            <img src="data:image/png;base64,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" alt="Dilithion" width="40" height="40" style="border-radius: 50%; background: rgba(255,255,255,0.12); padding: 2px;">
            <span class="logo-text">Dilithion</span>
        </div>

        <div class="nav-section">
            <div class="nav-section-title">Wallet</div>
            <div class="nav-item active" data-page="dashboard">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <rect x="3" y="3" width="7" height="7"></rect>
                    <rect x="14" y="3" width="7" height="7"></rect>
                    <rect x="14" y="14" width="7" height="7"></rect>
                    <rect x="3" y="14" width="7" height="7"></rect>
                </svg>
                <span>Dashboard</span>
            </div>
            <div class="nav-item" data-page="send">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <line x1="22" y1="2" x2="11" y2="13"></line>
                    <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>
                </svg>
                <span>Send</span>
            </div>
            <div class="nav-item" data-page="receive">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="22 12 16 12 14 15 10 15 8 12 2 12"></polyline>
                    <path d="M5.45 5.11L2 12v6a2 2 0 002 2h16a2 2 0 002-2v-6l-3.45-6.89A2 2 0 0016.76 4H7.24a2 2 0 00-1.79 1.11z"></path>
                </svg>
                <span>Receive</span>
            </div>
            <div class="nav-item" data-page="transactions">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="22 7 13.5 15.5 8.5 10.5 2 17"></polyline>
                    <polyline points="16 7 22 7 22 13"></polyline>
                </svg>
                <span>History</span>
            </div>
            <div class="nav-item" data-page="backup">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                </svg>
                <span>Backup & Recover</span>
            </div>
        </div>

        <div class="nav-section">
            <div class="nav-section-title">Network</div>
            <div class="nav-item" data-page="network">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="12" cy="12" r="10"></circle>
                    <line x1="2" y1="12" x2="22" y2="12"></line>
                    <path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"></path>
                </svg>
                <span>Blockchain</span>
            </div>
            <div class="nav-item" data-page="mining-stats">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M12 2L2 7l10 5 10-5-10-5z"></path>
                    <path d="M2 17l10 5 10-5"></path>
                    <path d="M2 12l10 5 10-5"></path>
                </svg>
                <span>Mining Stats</span>
            </div>
        </div>

        <div class="nav-section">
            <div class="nav-section-title">Bridge</div>
            <div class="nav-item" data-page="bridge">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"></path>
                    <line x1="4" y1="22" x2="4" y2="15"></line>
                </svg>
                <span>Bridge</span>
            </div>
        </div>

        <div class="nav-section">
            <div class="nav-section-title">Settings</div>
            <div class="nav-item" data-page="settings">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="12" cy="12" r="3"></circle>
                    <path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-2 2 2 2 0 01-2-2v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83 0 2 2 0 010-2.83l.06-.06a1.65 1.65 0 00.33-1.82 1.65 1.65 0 00-1.51-1H3a2 2 0 01-2-2 2 2 0 012-2h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 010-2.83 2 2 0 012.83 0l.06.06a1.65 1.65 0 001.82.33H9a1.65 1.65 0 001-1.51V3a2 2 0 012-2 2 2 0 012 2v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 0 2 2 0 010 2.83l-.06.06a1.65 1.65 0 00-.33 1.82V9a1.65 1.65 0 001.51 1H21a2 2 0 012 2 2 2 0 01-2 2h-.09a1.65 1.65 0 00-1.51 1z"></path>
                </svg>
                <span>Settings</span>
            </div>
        </div>

        <!-- Chain Selector -->
        <div style="padding: 12px 16px; border-top: 1px solid var(--border);">
            <div style="font-size: 0.65rem; text-transform: uppercase; letter-spacing: 1px; color: var(--text-muted); margin-bottom: 8px;">Chain</div>
            <div id="chainSelector" style="display: flex; background: var(--bg-darker); border-radius: 8px; padding: 3px; gap: 2px;">
                <button id="chainBtnDil" onclick="switchChain('dil')" style="flex:1; padding: 6px 0; border: none; border-radius: 6px; font-size: 0.75rem; font-weight: 600; cursor: pointer; transition: all 0.2s; background: var(--primary); color: white;">DIL</button>
                <button id="chainBtnDilv" onclick="switchChain('dilv')" style="flex:1; padding: 6px 0; border: none; border-radius: 6px; font-size: 0.75rem; font-weight: 600; cursor: pointer; transition: all 0.2s; background: transparent; color: var(--text-muted);">DilV</button>
            </div>
        </div>

        <div class="connection-status" style="cursor: pointer;" onclick="navigateTo('settings')" title="Click to configure connection">
            <div class="status-indicator">
                <div class="status-dot" id="statusDot"></div>
                <span id="statusText">Connecting...</span>
            </div>
            <button id="reconnectBtn" class="btn btn-secondary" style="margin-top: 8px; padding: 6px 12px; font-size: 0.75rem; display: none;" onclick="event.stopPropagation(); connect();">Reconnect</button>
        </div>
    </nav>

    <!-- Mobile Bottom Navigation (hidden on desktop) -->
    <nav class="mobile-nav" id="mobileNav">
        <div class="mobile-nav-item active" data-mobile-page="dashboard" onclick="mobileNavigate('dashboard')">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect></svg>
            <span>Home</span>
        </div>
        <div class="mobile-nav-item" data-mobile-page="send" onclick="mobileNavigate('send')">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="22" y1="2" x2="11" y2="13"></line><polygon points="22 2 15 22 11 13 2 9 22 2"></polygon></svg>
            <span>Send</span>
        </div>
        <div class="mobile-nav-item" data-mobile-page="receive" onclick="mobileNavigate('receive')">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 16 12 14 15 10 15 8 12 2 12"></polyline><path d="M5.45 5.11L2 12v6a2 2 0 002 2h16a2 2 0 002-2v-6l-3.45-6.89A2 2 0 0016.76 4H7.24a2 2 0 00-1.79 1.11z"></path></svg>
            <span>Receive</span>
        </div>
        <div class="mobile-nav-item" data-mobile-page="bridge" onclick="mobileNavigate('bridge')">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"></path><line x1="4" y1="22" x2="4" y2="15"></line></svg>
            <span>Bridge</span>
        </div>
        <div class="mobile-nav-item" onclick="toggleMobileMore()">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="5" r="1"></circle><circle cx="12" cy="12" r="1"></circle><circle cx="12" cy="19" r="1"></circle></svg>
            <span>More</span>
        </div>
    </nav>

    <!-- Mobile "More" Menu Overlay -->
    <div class="mobile-more-overlay" id="mobileMoreOverlay" onclick="if(event.target===this)toggleMobileMore()">
        <div class="mobile-more-sheet">
            <div class="mobile-more-item" onclick="mobileNavigate('transactions')">History</div>
            <div class="mobile-more-item" onclick="mobileNavigate('network')">Blockchain</div>
            <div class="mobile-more-item" onclick="mobileNavigate('backup')">Backup & Recover</div>
            <div class="mobile-more-item" onclick="mobileNavigate('settings')">Settings</div>
            <div style="display: flex; gap: 8px; padding: 12px 0; border-top: 1px solid var(--border); margin-top: 8px;">
                <button id="mChainDil" onclick="switchChain('dil');toggleMobileMore()" style="flex:1; padding: 10px; border: none; border-radius: 8px; font-weight: 600; cursor: pointer; background: var(--primary); color: white;">DIL</button>
                <button id="mChainDilv" onclick="switchChain('dilv');toggleMobileMore()" style="flex:1; padding: 10px; border: none; border-radius: 8px; font-weight: 600; cursor: pointer; background: transparent; color: var(--text-muted); border: 1px solid var(--border);">DilV</button>
            </div>
        </div>
    </div>

    <!-- Main Content -->
    <main class="main-content">
        <!-- Welcome Page (shown when no wallet exists in light mode) -->
        <div class="page" id="page-welcome" style="display: none;">
            <div style="max-width: 520px; margin: 40px auto; text-align: center;">
                <div style="font-size: 3rem; margin-bottom: 16px;">&#x1f6e1;</div>
                <h1 style="font-family: 'DM Serif Display', serif; font-size: 1.8rem; margin-bottom: 8px;">Welcome to Dilithion</h1>
                <p style="color: var(--text-secondary); margin-bottom: 32px; line-height: 1.6;">
                    Quantum-resistant wallet — your keys stay in your browser. No account, no signup, no server.
                </p>

                <div style="display: flex; flex-direction: column; gap: 16px; text-align: left;">
                    <!-- Create New Wallet -->
                    <div class="card" style="cursor: pointer; transition: border-color 0.2s;" onclick="welcomeCreate()" onmouseover="this.style.borderColor='var(--primary)'" onmouseout="this.style.borderColor='var(--border)'">
                        <div style="display: flex; align-items: center; gap: 16px;">
                            <div style="width: 48px; height: 48px; background: rgba(200,162,78,0.15); border-radius: 12px; display: flex; align-items: center; justify-content: center; flex-shrink: 0;">
                                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
                            </div>
                            <div>
                                <div style="font-weight: 600; font-size: 1rem; margin-bottom: 4px;">Create New Wallet</div>
                                <div style="color: var(--text-secondary); font-size: 0.85rem;">Generate a new wallet with a 24-word recovery phrase</div>
                            </div>
                        </div>
                    </div>

                    <!-- Import Existing Wallet -->
                    <div class="card" style="cursor: pointer; transition: border-color 0.2s;" onclick="welcomeImport()" onmouseover="this.style.borderColor='var(--primary)'" onmouseout="this.style.borderColor='var(--border)'">
                        <div style="display: flex; align-items: center; gap: 16px;">
                            <div style="width: 48px; height: 48px; background: rgba(200,162,78,0.15); border-radius: 12px; display: flex; align-items: center; justify-content: center; flex-shrink: 0;">
                                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
                            </div>
                            <div>
                                <div style="font-weight: 600; font-size: 1rem; margin-bottom: 4px;">Import Existing Wallet</div>
                                <div style="color: var(--text-secondary); font-size: 0.85rem;">Restore using your 24-word recovery phrase from a node or backup</div>
                            </div>
                        </div>
                    </div>
                    <!-- Unlock Existing (shown when a wallet already exists in browser) -->
                    <div class="card" id="welcomeUnlockCard" style="display: none; cursor: pointer; transition: border-color 0.2s;" onclick="welcomeShowUnlock()" onmouseover="this.style.borderColor='var(--primary)'" onmouseout="this.style.borderColor='var(--border)'">
                        <div style="display: flex; align-items: center; gap: 16px;">
                            <div style="width: 48px; height: 48px; background: rgba(34,197,94,0.15); border-radius: 12px; display: flex; align-items: center; justify-content: center; flex-shrink: 0;">
                                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0110 0v4"></path></svg>
                            </div>
                            <div>
                                <div style="font-weight: 600; font-size: 1rem; margin-bottom: 4px;">Unlock Existing Wallet</div>
                                <div style="color: var(--text-secondary); font-size: 0.85rem;">You have a wallet saved in this browser. Enter your password to unlock it.</div>
                            </div>
                        </div>
                    </div>

                </div>
            </div>

            <!-- Unlock Existing Flow -->
            <div id="welcomeUnlockFlow" style="display: none; max-width: 520px; margin: 0 auto;">
                <div class="card">
                    <div class="card-title">Unlock Wallet</div>
                    <div class="form-group">
                        <label class="form-label">Password</label>
                        <input type="password" class="form-input" id="welcomeUnlockPassword" placeholder="Enter your wallet password" onkeypress="if(event.key==='Enter')welcomeDoUnlock()">
                    </div>
                    <button class="btn btn-primary" onclick="welcomeDoUnlock()" style="width: 100%;">Unlock</button>
                    <button class="btn" onclick="welcomeUnlockBack()" style="width: 100%; margin-top: 8px; background: transparent; color: var(--text-secondary);">Back</button>
                    <p style="text-align: center; margin-top: 12px; font-size: 0.8rem; color: var(--text-muted);">
                        Forgot your password? Go back and choose <strong>Restore Wallet</strong> using your 24-word recovery phrase.
                    </p>
                </div>
            </div>

            <!-- Create Wallet Flow -->
            <div id="welcomeCreateFlow" style="display: none; max-width: 520px; margin: 0 auto;">
                <div class="card">
                    <div class="card-title">Create New Wallet</div>
                    <div class="form-group">
                        <label class="form-label">Choose a password (8+ characters)</label>
                        <div style="position: relative;">
                            <input type="password" class="form-input" id="welcomeCreatePassword" placeholder="Password to encrypt your wallet" style="padding-right: 48px;">
                            <span onclick="const i=document.getElementById('welcomeCreatePassword');i.type=i.type==='password'?'text':'password';this.textContent=i.type==='password'?'Show':'Hide'" style="position:absolute;right:12px;top:50%;transform:translateY(-50%);cursor:pointer;font-size:0.75rem;color:var(--text-muted);user-select:none;">Show</span>
                        </div>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Confirm password</label>
                        <div style="position: relative;">
                            <input type="password" class="form-input" id="welcomeCreatePasswordConfirm" placeholder="Re-enter your password" style="padding-right: 48px;">
                            <span onclick="const i=document.getElementById('welcomeCreatePasswordConfirm');i.type=i.type==='password'?'text':'password';this.textContent=i.type==='password'?'Show':'Hide'" style="position:absolute;right:12px;top:50%;transform:translateY(-50%);cursor:pointer;font-size:0.75rem;color:var(--text-muted);user-select:none;">Show</span>
                        </div>
                    </div>
                    <button class="btn btn-primary" onclick="welcomeDoCreate()" style="width: 100%;">Create Wallet</button>
                </div>
            </div>

            <!-- Mnemonic Display (after creation) -->
            <div id="welcomeMnemonicDisplay" style="display: none; max-width: 520px; margin: 0 auto;">
                <div class="card" style="border-color: var(--warning);">
                    <div class="card-title" style="color: var(--warning);">Write Down Your Recovery Phrase</div>
                    <div style="background: rgba(245,158,11,0.1); border: 1px solid rgba(245,158,11,0.3); border-radius: 8px; padding: 12px; margin-bottom: 16px; font-size: 0.85rem; color: var(--warning); line-height: 1.6;">
                        <strong>This is the ONLY time your recovery phrase will be shown.</strong><br>
                        Write it down on paper and store it in a secure location. Anyone with these 24 words can access your funds. Never share it. Never store it digitally.
                    </div>
                    <div id="welcomeMnemonicWords" style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; margin-bottom: 16px;"></div>
                    <div style="background: var(--bg-darker); border-radius: 8px; padding: 12px; margin-bottom: 16px; font-size: 0.8rem; color: var(--text-muted); line-height: 1.6;">
                        <strong style="color: var(--text-secondary);">Tips:</strong><br>
                        - Write it on paper, not digitally<br>
                        - Store in a fireproof/waterproof location<br>
                        - Consider a metal backup for extra durability<br>
                        - Never take a photo or screenshot
                    </div>
                    <div class="form-group">
                        <label class="form-label">Your wallet address</label>
                        <div id="welcomeAddress" style="background: var(--bg-darker); border: 1px solid var(--border); border-radius: 8px; padding: 10px 14px; font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: var(--accent); word-break: break-all; cursor: pointer;" onclick="navigator.clipboard.writeText(this.textContent).then(()=>{showNotification('Address copied!','success')})"></div>
                    </div>
                    <button class="btn btn-primary" onclick="welcomeFinish()" style="width: 100%;">I have written it down — Continue to wallet</button>
                </div>
            </div>

            <!-- Import Wallet Flow -->
            <div id="welcomeImportFlow" style="display: none; max-width: 520px; margin: 0 auto;">
                <div class="card">
                    <div class="card-title">Import Wallet</div>
                    <p style="color: var(--text-secondary); font-size: 0.85rem; margin-bottom: 16px;">
                        Enter the 24-word recovery phrase from your node wallet or paper backup.
                    </p>
                    <div class="form-group">
                        <label class="form-label">Recovery phrase (24 words)</label>
                        <textarea class="form-input" id="welcomeImportMnemonic" rows="4" placeholder="Enter your 24 words separated by spaces" style="resize: vertical; font-family: 'JetBrains Mono', monospace;"></textarea>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Browser wallet password (8+ characters)</label>
                        <div style="position: relative;">
                            <input type="password" class="form-input" id="welcomeImportPassword" placeholder="Password to protect your wallet in this browser" style="padding-right: 48px;">
                            <span onclick="const i=document.getElementById('welcomeImportPassword');i.type=i.type==='password'?'text':'password';this.textContent=i.type==='password'?'Show':'Hide'" style="position:absolute;right:12px;top:50%;transform:translateY(-50%);cursor:pointer;font-size:0.75rem;color:var(--text-muted);user-select:none;">Show</span>
                        </div>
                        <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 4px; line-height: 1.4;">
                            This encrypts your keys in the browser. You can use the same password as your node wallet, or choose a different one.
                        </div>
                    </div>
                    <button class="btn btn-primary" onclick="welcomeDoImport()" style="width: 100%;">Import Wallet</button>
                    <button class="btn" onclick="welcomeImportBack()" style="width: 100%; margin-top: 8px; background: transparent; color: var(--text-secondary);">Back</button>
                </div>
            </div>
        </div>

        <!-- Dashboard Page -->
        <div class="page active" id="page-dashboard">
            <div class="page-header">
                <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px;">
                    <h1 class="page-title" style="margin: 0;">HD Wallet Dashboard</h1>
                    <button class="btn btn-secondary" onclick="toggleAddressList()" id="showAddressesBtn" style="padding: 8px 16px; font-size: 13px;">
                        Show All Addresses
                    </button>
                </div>
                <p class="page-subtitle">Your wallet overview</p>
            </div>

            <!-- All Addresses Panel (toggled by Show All Addresses button) -->
            <div id="addressListPanel" class="card" style="display: none; margin-bottom: 16px;">
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px;">
                    <div class="card-title" style="margin: 0;">All Wallet Addresses</div>
                    <button class="btn btn-secondary" onclick="toggleAddressList()" style="padding: 4px 12px; font-size: 12px;">Close</button>
                </div>
                <p style="color: #8A8A80; font-size: 12px; margin: 0 0 12px 0;">Your HD wallet derives multiple addresses. Mining rewards and received funds may be on different addresses.</p>
                <div id="addressListContent" style="display: flex; flex-direction: column; gap: 4px;">
                    <div style="color: #8A8A80; font-size: 13px; padding: 12px 0;">Loading...</div>
                </div>
            </div>

            <!-- Mobile Chain Toggle (hidden on desktop — sidebar has it) -->
            <div class="mobile-chain-toggle" id="mobileChainToggle" style="display: none; margin-bottom: 16px;">
                <div style="display: flex; gap: 4px; background: var(--bg-darker); border-radius: 10px; padding: 4px;">
                    <button id="mobileChainDil" onclick="switchChain('dil')" style="flex: 1; padding: 12px; border: none; border-radius: 8px; font-weight: 600; font-size: 0.95rem; cursor: pointer; transition: all 0.2s; background: var(--primary); color: white;">DIL</button>
                    <button id="mobileChainDilv" onclick="switchChain('dilv')" style="flex: 1; padding: 12px; border: none; border-radius: 8px; font-weight: 600; font-size: 0.95rem; cursor: pointer; transition: all 0.2s; background: transparent; color: var(--text-muted);">DilV</button>
                </div>
            </div>

            <div class="balance-grid">
                <div class="balance-card total">
                    <div class="balance-label">Total Balance</div>
                    <div class="balance-amount">
                        <span id="totalBalance">0.00000000</span>
                        <span class="balance-unit">DIL</span>
                    </div>
                </div>
                <div class="balance-card">
                    <div class="balance-label">Available (Mature)</div>
                    <div class="balance-amount">
                        <span id="matureBalance">0.00000000</span>
                        <span class="balance-unit">DIL</span>
                    </div>
                </div>
                <div class="balance-card">
                    <div class="balance-label">Pending (Immature)</div>
                    <div class="balance-amount">
                        <span id="immatureBalance">0.00000000</span>
                        <span class="balance-unit">DIL</span>
                    </div>
                </div>
            </div>

            <!-- Light Wallet Unlock Prompt (shown when wallet is locked in light mode) -->
            <div id="dashboardUnlockPrompt" style="display: none; background: rgba(200,162,78,0.08); border: 1px solid rgba(200,162,78,0.3); border-radius: 10px; padding: 16px 20px; margin-bottom: 16px; display: none;">
                <div style="display: flex; align-items: center; gap: 16px; flex-wrap: wrap;">
                    <div style="flex: 1; min-width: 200px;">
                        <div style="font-weight: 600; color: var(--text-primary); margin-bottom: 4px;">Wallet is locked</div>
                        <div style="font-size: 0.85rem; color: var(--text-secondary);">Enter your password to view your balance and manage funds.</div>
                    </div>
                    <div style="display: flex; gap: 8px; align-items: center;">
                        <input type="password" class="form-input" id="dashboardUnlockPw" placeholder="Password" style="width: 180px; padding: 8px 12px;" onkeypress="if(event.key==='Enter')dashboardQuickUnlock()">
                        <button class="btn btn-primary" onclick="dashboardQuickUnlock()" style="padding: 8px 16px; white-space: nowrap;">Unlock</button>
                    </div>
                </div>
                <div style="margin-top: 8px; font-size: 0.8rem; color: var(--text-muted);">
                    Forgot your password? Go to Settings and restore your wallet using your 24-word recovery phrase.
                </div>
            </div>

            <!-- Chain Health Warning Banner -->
            <div id="chainWarning" style="display:none; color:#ff4444; background:#1a0000; padding:12px 16px; margin-bottom:16px; border:1px solid #ff4444; border-radius:8px; font-weight:600;"></div>

            <!-- Wallet Optimization Banner (shown when too many small UTXOs) -->
            <div id="optimizeBanner" style="display:none; background: rgba(200,162,78,0.08); border: 1px solid rgba(200,162,78,0.3); border-radius: 10px; padding: 16px 20px; margin-bottom: 16px;">
                <div style="display: flex; align-items: center; gap: 16px; flex-wrap: wrap;">
                    <div style="flex: 1; min-width: 200px;">
                        <div style="font-weight: 600; color: var(--text-primary); margin-bottom: 4px;">
                            Wallet needs optimization
                        </div>
                        <div style="font-size: 0.85rem; color: var(--text-secondary);">
                            Mining creates many small payments. Combining them makes sending faster and cheaper.
                            <span id="optimizeUtxoCount"></span>
                        </div>
                    </div>
                    <button class="btn btn-primary" id="optimizeBtn" onclick="optimizeWallet()" style="white-space: nowrap;">
                        Optimize Now
                    </button>
                </div>
            </div>

            <!-- Wallet Encryption Warning Banner (shown when wallet is NOT encrypted) -->
            <div id="encryptionWarningBanner" style="display: none; background: rgba(255,68,68,0.06); border: 1px solid rgba(255,68,68,0.4); border-radius: 10px; padding: 20px; margin-bottom: 16px;">
                <div style="display: flex; align-items: flex-start; gap: 12px; margin-bottom: 16px;">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#ff4444" stroke-width="2" style="flex-shrink: 0; margin-top: 2px;">
                        <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"></path>
                        <line x1="12" y1="9" x2="12" y2="13"></line>
                        <line x1="12" y1="17" x2="12.01" y2="17"></line>
                    </svg>
                    <div>
                        <div style="font-weight: 700; color: #ff4444; font-size: 1rem; margin-bottom: 4px;">Your wallet is not encrypted</div>
                        <div style="font-size: 0.85rem; color: var(--text-secondary); line-height: 1.5;">
                            Anyone with access to your computer can spend your funds. Set a password to protect your wallet.
                        </div>
                    </div>
                </div>
                <div id="encryptBannerForm">
                    <div style="display: flex; flex-direction: column; gap: 10px;">
                        <div style="position: relative;">
                            <input type="password" class="form-input" id="bannerEncryptPw" placeholder="Enter password (min 8 characters)" style="padding-right: 50px;">
                            <button type="button" onclick="togglePasswordVisibility('bannerEncryptPw', this)" style="position: absolute; right: 8px; top: 50%; transform: translateY(-50%); background: none; border: none; color: var(--text-muted); cursor: pointer; padding: 4px 8px; font-size: 0.85rem;">Show</button>
                        </div>
                        <div style="position: relative;">
                            <input type="password" class="form-input" id="bannerEncryptPwConfirm" placeholder="Confirm password" style="padding-right: 50px;">
                            <button type="button" onclick="togglePasswordVisibility('bannerEncryptPwConfirm', this)" style="position: absolute; right: 8px; top: 50%; transform: translateY(-50%); background: none; border: none; color: var(--text-muted); cursor: pointer; padding: 4px 8px; font-size: 0.85rem;">Show</button>
                        </div>
                        <div style="display: flex; gap: 12px; align-items: center;">
                            <button class="btn btn-primary" onclick="encryptFromBanner()" style="padding: 10px 24px;">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 6px; vertical-align: middle;">
                                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                                    <path d="M7 11V7a5 5 0 0110 0v4"></path>
                                </svg>
                                Encrypt Wallet
                            </button>
                            <span style="font-size: 0.8rem; color: var(--text-muted);">You'll need this password to unlock for mining &amp; sending</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Wallet Encrypted Confirmation (shown briefly after encrypting, or on load when encrypted) -->
            <div id="encryptionOkBanner" style="display: none; background: rgba(76,175,80,0.06); border: 1px solid rgba(76,175,80,0.3); border-radius: 10px; padding: 14px 20px; margin-bottom: 16px;">
                <div style="display: flex; align-items: center; gap: 12px;">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#4caf50" stroke-width="2" style="flex-shrink: 0;">
                        <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                        <path d="M7 11V7a5 5 0 0110 0v4"></path>
                    </svg>
                    <span style="font-size: 0.9rem; color: #4caf50; font-weight: 600;">Wallet is encrypted</span>
                </div>
            </div>

            <!-- Node Wallet Security Card (Dashboard) -->
            <div class="card" id="dashboardWalletSecurity" style="margin-bottom: 16px; display: none;">
                <div class="card-title">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 8px; vertical-align: middle;">
                        <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                        <path d="M7 11V7a5 5 0 0110 0v4"></path>
                    </svg>
                    Node Wallet Security
                </div>
                <div style="display: flex; align-items: center; justify-content: space-between;">
                    <div style="display: flex; align-items: center; gap: 12px;">
                        <span id="dashWalletLockIcon" style="font-size: 1.5rem;">🔓</span>
                        <div>
                            <div id="dashWalletLockStatus" style="font-weight: 600;">Unlocked</div>
                            <div id="dashWalletLockHint" style="font-size: 0.8rem; color: var(--text-muted);">Wallet is ready for mining</div>
                        </div>
                    </div>
                    <button id="dashLockBtn" class="btn btn-secondary" onclick="toggleNodeWalletLock()" style="padding: 8px 16px;">
                        🔒 Lock Wallet
                    </button>
                </div>
                <div id="dashUnlockForm" style="display: none; margin-top: 16px; padding-top: 16px; border-top: 1px solid var(--border-color);">
                    <div style="display: flex; gap: 12px; align-items: flex-end;">
                        <div style="flex: 1;">
                            <label class="form-label" style="font-size: 0.85rem;">Password</label>
                            <input type="password" id="dashUnlockPassword" class="form-input" placeholder="Enter wallet password">
                        </div>
                        <button class="btn btn-primary" onclick="unlockNodeWalletFromDash()">Unlock</button>
                    </div>
                    <p style="font-size: 0.8rem; color: var(--text-muted); margin-top: 8px;">
                        Mining requires wallet to be unlocked for block signing
                    </p>
                    <p style="font-size: 0.8rem; color: var(--text-muted); margin-top: 4px;">
                        Forgot your password? Stop the node, restart it, and restore from your 24-word recovery phrase.
                    </p>
                </div>
            </div>

            <div class="cards-row" style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
                <!-- Mining Card (hidden on mobile/light mode) -->
                <div class="card mining-only" id="dashMiningCard">
                    <div class="card-title">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 8px; vertical-align: middle;">
                            <path d="M12 2L2 7l10 5 10-5-10-5z"></path>
                            <path d="M2 17l10 5 10-5"></path>
                            <path d="M2 12l10 5 10-5"></path>
                        </svg>
                        Mining
                    </div>
                    <div style="display: flex; gap: 12px; margin-bottom: 16px;">
                        <button id="miningToggle" class="btn btn-primary" onclick="toggleMining()">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <polygon points="5 3 19 12 5 21 5 3"></polygon>
                            </svg>
                            <span id="miningBtnText">Start Mining</span>
                        </button>
                        <select id="miningThreads" class="form-input" style="width: auto; padding: 8px 12px;" onchange="handleThreadChange()">
                            <option value="2">2 Threads</option>
                            <option value="4" selected>4 Threads</option>
                            <option value="8">8 Threads</option>
                            <option value="max">Maximum</option>
                            <option value="custom">Custom...</option>
                        </select>
                        <input type="number" id="customThreads" class="form-input" style="width: 70px; padding: 8px 12px; display: none;" min="1" max="256" placeholder="#">
                    </div>
                    <div class="info-grid" style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
                        <div class="info-item">
                            <span class="info-label" style="color: #8A8A80; font-size: 12px;">Status</span>
                            <span class="info-value" style="display: flex; align-items: center; gap: 6px;">
                                <span id="miningStatusDot" class="status-dot" style="width: 8px; height: 8px; border-radius: 50%; background: #666;"></span>
                                <span id="miningStatus">Stopped</span>
                            </span>
                        </div>
                        <div class="info-item">
                            <span class="info-label" style="color: #8A8A80; font-size: 12px;">Hash Rate</span>
                            <span class="info-value" id="dashHashRate">0 H/s</span>
                        </div>
                        <div class="info-item">
                            <span class="info-label" style="color: #8A8A80; font-size: 12px;" title="Both numbers are for this node session (reset on restart). Accepted = blocks currently on the canonical chain mined by your MIK. Submitted = VDF blocks your miner has solved and broadcast. Gap is expected: DilV uses lowest-VDF-output-wins distribution, so competing miners' lower outputs cause some of your submitted blocks to be reorged out. Each identity earns roughly its fair share (≈ network_blocks / active_miners). Your wallet transaction history is the source of truth for lifetime rewards.">Blocks Mined &nbsp;<span style="opacity:0.5;">ⓘ</span></span>
                            <span class="info-value" id="blocksFound">0</span>
                        </div>
                        <div class="info-item">
                            <span class="info-label" style="color: #8A8A80; font-size: 12px;">Est. Time to Block</span>
                            <span class="info-value" id="etaToBlock">N/A</span>
                        </div>
                    </div>
                    <div id="miningAddressRow" style="margin-top: 12px; padding-top: 12px; border-top: 1px solid rgba(138,138,128,0.15); display: none;">
                        <span class="info-label" style="color: #8A8A80; font-size: 12px;">Rewards Address</span>
                        <div style="display: flex; align-items: center; gap: 8px; margin-top: 4px;">
                            <span id="miningAddressText" style="font-family: monospace; font-size: 13px; color: #C8B560; word-break: break-all; flex: 1;">—</span>
                            <button class="copy-btn" onclick="copyMiningAddress()" style="flex-shrink: 0; padding: 4px 10px; font-size: 11px;">Copy</button>
                        </div>
                    </div>
                </div>

                <!-- Quick Actions Card -->
                <div class="card">
                    <div class="card-title">Quick Actions</div>
                    <div style="display: flex; flex-direction: column; gap: 12px;">
                        <button class="btn btn-primary" onclick="navigateTo('send')">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <line x1="22" y1="2" x2="11" y2="13"></line>
                                <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>
                            </svg>
                            Send <span class="chain-label">DIL</span>
                        </button>
                        <button class="btn btn-secondary" onclick="navigateTo('receive')">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <polyline points="22 12 16 12 14 15 10 15 8 12 2 12"></polyline>
                                <path d="M5.45 5.11L2 12v6a2 2 0 002 2h16a2 2 0 002-2v-6l-3.45-6.89A2 2 0 0016.76 4H7.24a2 2 0 00-1.79 1.11z"></path>
                            </svg>
                            Receive <span class="chain-label">DIL</span>
                        </button>
                        <button class="btn btn-secondary" onclick="rescanWallet()">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <polyline points="23 4 23 10 17 10"></polyline>
                                <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path>
                            </svg>
                            <span id="rescanBtnText">Refresh Balances</span>
                        </button>
                        <button class="btn btn-secondary light-only" id="lockWalletBtn" onclick="lockAndSwitch()" style="display: none;">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                                <path d="M7 11V7a5 5 0 0110 0v4"></path>
                            </svg>
                            Lock / Switch Wallet
                        </button>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-title">Recent Transactions</div>
                <div id="recentTxList" class="tx-list">
                    <div class="loading">
                        <div class="spinner"></div>
                        Loading transactions...
                    </div>
                </div>
            </div>
        </div>

        <!-- Send Page -->
        <div class="page" id="page-send">
            <div class="page-header">
                <h1 class="page-title">Send <span class="chain-label">DIL</span></h1>
                <p class="page-subtitle">Transfer funds to another address</p>
            </div>

            <div class="card">
                <div id="sendAlert"></div>
                <form id="sendForm" onsubmit="handleSend(event)">
                    <div class="form-group">
                        <label class="form-label">Recipient Address</label>
                        <input type="text" class="form-input" id="sendAddress" placeholder="dil1..." required>
                        <div class="form-hint">Enter the recipient's Dilithion address</div>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Amount (<span class="chain-label">DIL</span>)</label>
                        <input type="number" class="form-input" id="sendAmount" placeholder="0.00000000" step="0.00000001" min="0.00000001" required>
                        <div class="form-hint">Available: <span id="availableForSend">0.00000000</span> <span class="chain-label">DIL</span></div>
                    </div>
                    <button type="submit" class="btn btn-primary" id="sendBtn">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <line x1="22" y1="2" x2="11" y2="13"></line>
                            <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>
                        </svg>
                        Send Transaction
                    </button>
                </form>
            </div>
        </div>

        <!-- Receive Page -->
        <div class="page" id="page-receive">
            <div class="page-header">
                <h1 class="page-title">Receive <span class="chain-label">DIL</span></h1>
                <p class="page-subtitle">Share your address to receive funds</p>
            </div>

            <div class="card" id="miningAddressCard" style="display: none; border-left: 3px solid #C8B560;">
                <div class="card-title" style="color: #C8B560;">Mining Rewards Address</div>
                <p style="color: #8A8A80; font-size: 13px; margin: 0 0 8px 0;">This is where your mining rewards are sent. Use this to check your balance on the explorer.</p>
                <div class="address-display">
                    <span class="address-text" id="receiveMiningAddress" style="font-family: monospace;">Loading...</span>
                    <button class="copy-btn" onclick="copyMiningAddress()">Copy</button>
                </div>
            </div>

            <div class="card">
                <div class="card-title">Your Receiving Address</div>
                <div class="address-display">
                    <span class="address-text" id="receiveAddress">Loading...</span>
                    <button class="copy-btn" onclick="copyAddress()" id="copyBtn">Copy</button>
                </div>
                <div class="qr-container" id="qrContainer" style="display: none;">
                    <canvas id="qrcode"></canvas>
                </div>
                <div style="margin-top: 16px; display: flex; gap: 8px;">
                    <input type="text" class="form-input" id="addressLabelInput" placeholder="Add a label (e.g., 'Mining Rewards')" style="flex: 1;">
                    <button class="btn btn-secondary" onclick="saveCurrentAddressLabel()">Save Label</button>
                </div>
                <div id="currentAddressLabel" style="margin-top: 8px; color: #8A8A80; font-size: 12px;"></div>
                <button class="btn btn-secondary" onclick="generateNewAddress()" style="width: 100%; margin-top: 12px;">
                    Generate New Address
                </button>
            </div>

        </div>

        <!-- Transactions Page -->
        <div class="page" id="page-transactions">
            <div class="page-header">
                <h1 class="page-title">Transaction History</h1>
                <p class="page-subtitle">All your wallet transactions</p>
            </div>

            <div class="card">
                <div id="txList" class="tx-list">
                    <div class="loading">
                        <div class="spinner"></div>
                        Loading transactions...
                    </div>
                </div>
            </div>
        </div>

        <!-- Network Page -->
        <div class="page" id="page-network">
            <div class="page-header">
                <h1 class="page-title">Blockchain Status</h1>
                <p class="page-subtitle">Network and chain information</p>
            </div>

            <div class="card">
                <div class="card-title">Chain Info</div>
                <div class="info-grid">
                    <div class="info-item">
                        <span class="info-label">Network</span>
                        <span class="info-value" id="networkName">-</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Block Height</span>
                        <span class="info-value" id="blockHeight">-</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Difficulty</span>
                        <span class="info-value" id="difficulty">-</span>
                    </div>
                </div>
                <div style="margin-top: 16px;">
                    <span class="info-label">Best Block Hash</span>
                    <div class="info-value" id="bestBlock" style="font-size: 0.75rem; margin-top: 4px; word-break: break-all;">-</div>
                </div>
            </div>

            <div class="card">
                <div class="card-title">Peer Connections</div>
                <div class="info-grid">
                    <div class="info-item">
                        <span class="info-label">Connected Peers</span>
                        <span class="info-value" id="peerCount">-</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Inbound</span>
                        <span class="info-value" id="inboundPeers">-</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Outbound</span>
                        <span class="info-value" id="outboundPeers">-</span>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-title">Mining Status</div>
                <div class="info-grid">
                    <div class="info-item">
                        <span class="info-label">Mining Active</span>
                        <span class="info-value" id="miningActive">-</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Hash Rate</span>
                        <span class="info-value" id="hashRate">-</span>
                    </div>
                </div>
            </div>
        </div>

        <!-- Mining Stats Page -->
        <div class="page" id="page-mining-stats">
            <div class="page-header">
                <h1 class="page-title">Mining Statistics</h1>
                <p class="page-subtitle">Network mining data and DFMP fairness status</p>
            </div>

            <!-- Network Mining Overview -->
            <div class="card">
                <div class="card-title">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 4px;">
                        <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline>
                    </svg>
                    Network Overview
                </div>
                <div class="info-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px;">
                    <div class="info-item">
                        <span class="info-label" style="color: #8A8A80; font-size: 12px;">Est. Network Hashrate</span>
                        <span class="info-value" id="msNetworkHashrate">-</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label" style="color: #8A8A80; font-size: 12px;">Difficulty</span>
                        <span class="info-value" id="msDifficulty">-</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label" style="color: #8A8A80; font-size: 12px;">Unique Miners (Window)</span>
                        <span class="info-value" id="msUniqueMiners">-</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label" style="color: #8A8A80; font-size: 12px;">Current Block Reward</span>
                        <span class="info-value" id="msBlockReward">-</span>
                    </div>
                </div>
            </div>

            <!-- DFMP Status -->
            <div class="card" id="msDfmpCard">
                <div class="card-title">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 4px;">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                    </svg>
                    DFMP Fair Mining Status
                </div>
                <div id="msDfmpContent">
                    <p style="color: var(--text-muted);">Loading DFMP data...</p>
                </div>
            </div>

            <!-- Miner Distribution -->
            <div class="card" id="msDistributionCard">
                <div class="card-title">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 4px;">
                        <rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect>
                        <line x1="3" y1="9" x2="21" y2="9"></line>
                        <line x1="9" y1="21" x2="9" y2="9"></line>
                    </svg>
                    Miner Distribution (Recent Window)
                </div>
                <div id="msDistributionContent">
                    <p style="color: var(--text-muted);">Loading miner distribution...</p>
                </div>
            </div>

            <!-- Calculator Link -->
            <div class="card" style="text-align: center; background: linear-gradient(135deg, rgba(200, 162, 78, 0.08), rgba(232, 200, 96, 0.08)); border-color: rgba(200, 162, 78, 0.2);">
                <p style="margin-bottom: 12px; color: var(--text-secondary);">Want to estimate your mining rewards before starting?</p>
                <a href="mining-calculator.html" target="_blank" style="display: inline-flex; align-items: center; gap: 8px; padding: 10px 20px; background: linear-gradient(135deg, var(--primary), var(--secondary)); color: white; border-radius: 8px; text-decoration: none; font-weight: 600; font-size: 0.9rem;">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <rect x="4" y="4" width="16" height="16" rx="2" ry="2"></rect>
                        <rect x="9" y="9" width="6" height="6"></rect>
                    </svg>
                    Mining Rewards Estimator
                </a>
            </div>
        </div>

        <!-- Backup & Recovery Page -->
        <div class="page" id="page-backup">
            <div class="page-header">
                <h1 class="page-title">Backup & Recover</h1>
                <p class="page-subtitle">Secure your wallet with a recovery phrase</p>
            </div>

            <!-- Recovery Alert -->
            <div id="backupAlert"></div>

            <!-- Show Mnemonic Section -->
            <div class="card">
                <div class="card-title">Export Recovery Phrase</div>
                <p style="color: var(--text-secondary); margin-bottom: 16px;">
                    Your 24-word recovery phrase is the only way to restore your wallet.
                    Keep it safe and never share it with anyone.
                </p>
                <div id="mnemonicDisplay" style="display: none;">
                    <div class="alert" style="background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.3); color: var(--warning); margin-bottom: 16px;">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width: 20px; height: 20px; flex-shrink: 0;">
                            <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"></path>
                            <line x1="12" y1="9" x2="12" y2="13"></line>
                            <line x1="12" y1="17" x2="12.01" y2="17"></line>
                        </svg>
                        <span>Write down these words in order and store them securely offline. Anyone with this phrase can access your funds.</span>
                    </div>
                    <div class="mnemonic-grid" id="mnemonicWords" style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin-bottom: 16px;">
                    </div>
                    <button class="btn btn-secondary" onclick="hideMnemonic()">Hide Recovery Phrase</button>
                </div>
                <div id="mnemonicHidden">
                    <div class="form-group">
                        <label class="form-label">Wallet Password (if encrypted)</label>
                        <input type="password" class="form-input" id="exportPassword" placeholder="Enter your wallet password">
                    </div>
                    <button class="btn btn-primary" onclick="showMnemonic()">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width: 16px; height: 16px;">
                            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                            <circle cx="12" cy="12" r="3"></circle>
                        </svg>
                        Show Recovery Phrase
                    </button>
                </div>
            </div>

            <!-- Recover Wallet Section -->
            <div class="card">
                <div class="card-title">Recover Wallet</div>
                <p style="color: var(--text-secondary); margin-bottom: 16px;">
                    Restore your wallet using your 24-word recovery phrase. This will only work on an empty wallet.
                </p>
                <div class="form-group">
                    <label class="form-label">Recovery Phrase (24 words)</label>
                    <textarea class="form-input" id="recoveryMnemonic" rows="4" placeholder="Enter your 24-word recovery phrase, separated by spaces" style="resize: vertical; font-family: 'JetBrains Mono', monospace;"></textarea>
                    <div class="form-hint">Enter all 24 words in the correct order, separated by spaces</div>
                </div>
                <div class="form-group">
                    <label class="form-label" id="recoveryPassphraseLabel">Passphrase (optional)</label>
                    <input type="password" class="form-input" id="recoveryPassphrase" placeholder="Leave empty if you didn't set a passphrase">
                    <div class="form-hint" id="recoveryPassphraseHint">Only enter if you used a passphrase when creating the wallet</div>
                </div>
                <button class="btn btn-primary" onclick="recoverWallet()">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width: 16px; height: 16px;">
                        <polyline points="1 4 1 10 7 10"></polyline>
                        <path d="M3.51 15a9 9 0 1014.85-9.36L1 10"></path>
                    </svg>
                    Recover Wallet
                </button>
            </div>

            <!-- Security Tips -->
            <div class="card">
                <div class="card-title">Security Tips</div>
                <ul style="color: var(--text-secondary); margin-left: 20px; line-height: 1.8;">
                    <li>Never share your recovery phrase with anyone</li>
                    <li>Write it down on paper and store it in a secure location</li>
                    <li>Consider using a metal backup for fire/water resistance</li>
                    <li>Never store your recovery phrase digitally or take photos of it</li>
                    <li>Verify your backup works before storing significant funds</li>
                </ul>
            </div>
        </div>

        <!-- Settings Page -->
        <div class="page" id="page-settings">
            <div class="page-header">
                <h1 class="page-title">Settings</h1>
                <p class="page-subtitle">Configure your wallet connection</p>
            </div>

            <!-- Wallet Setup (always shown - keys always in browser) -->
            <div class="card" id="walletSetupCard">
                <div class="card-title">🔐 Your Wallet</div>
                <p style="color: var(--text-secondary); margin-bottom: 16px; font-size: 0.9rem;">
                    Your private keys are stored securely in your browser. Same wallet works in both connection modes.
                </p>

                <!-- No wallet exists -->
                <div id="lightWalletCreate">
                    <p style="color: var(--text-secondary); margin-bottom: 16px;">
                        Create a new wallet or restore from your 24-word recovery phrase.
                    </p>
                    <div style="display: flex; gap: 12px; flex-wrap: wrap;">
                        <button class="btn btn-primary" onclick="showCreateLightWallet()">
                            ➕ Create New Wallet
                        </button>
                        <button class="btn" onclick="showRestoreLightWallet()">
                            📥 Restore from Mnemonic
                        </button>
                    </div>
                </div>

                <!-- Wallet exists, needs unlock -->
                <div id="lightWalletUnlock" style="display: none;">
                    <p style="color: var(--text-secondary); margin-bottom: 16px;">
                        Enter your password to unlock your wallet.
                    </p>
                    <div class="form-group">
                        <label class="form-label">Password</label>
                        <input type="password" class="form-input" id="lightWalletPassword"
                               placeholder="Enter wallet password" onkeypress="if(event.key==='Enter')unlockLightWallet()">
                    </div>
                    <button class="btn btn-primary" onclick="unlockLightWallet()">🔓 Unlock Wallet</button>
                </div>

                <!-- Wallet unlocked -->
                <div id="lightWalletUnlocked" style="display: none;">
                    <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 16px;">
                        <span style="font-size: 1.5rem;">🔓</span>
                        <div>
                            <div style="font-weight: 600; color: var(--success);">Wallet Unlocked</div>
                            <div style="font-size: 0.8rem; color: var(--text-muted);" id="lightWalletAutoLock">Auto-locks in 5 minutes</div>
                        </div>
                    </div>
                    <div style="display: flex; gap: 12px; flex-wrap: wrap;">
                        <button class="btn" onclick="lockLightWallet()">🔒 Lock Now</button>
                        <button class="btn" onclick="showBackupMnemonic()">📝 Backup Mnemonic</button>
                    </div>
                </div>
            </div>

            <!-- Node Wallet Security (Full Node mode only) -->
            <div class="card" id="nodeWalletSecurityCard" style="display: none;">
                <div class="card-title">🔐 Node Wallet Security</div>
                <p style="color: var(--text-secondary); margin-bottom: 16px; font-size: 0.9rem;">
                    Manage encryption for your node's wallet file. This is separate from your browser wallet.
                </p>

                <!-- Not encrypted -->
                <div id="nodeWalletNotEncrypted">
                    <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 16px; padding: 12px; background: rgba(239, 68, 68, 0.1); border-radius: 8px;">
                        <span style="font-size: 1.2rem;">⚠️</span>
                        <div>
                            <div style="font-weight: 600; color: var(--error);">Wallet Not Encrypted</div>
                            <div style="font-size: 0.8rem; color: var(--text-muted);">Your node wallet file is not password protected</div>
                        </div>
                    </div>
                    <div class="form-group">
                        <label class="form-label">New Password (min 8 characters)</label>
                        <div style="position: relative;">
                            <input type="password" class="form-input" id="encryptWalletPassword" placeholder="Enter password" style="padding-right: 50px;">
                            <button type="button" onclick="togglePasswordVisibility('encryptWalletPassword', this)" style="position: absolute; right: 8px; top: 50%; transform: translateY(-50%); background: none; border: none; color: var(--text-muted); cursor: pointer; padding: 4px 8px; font-size: 0.85rem;">Show</button>
                        </div>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Confirm Password</label>
                        <div style="position: relative;">
                            <input type="password" class="form-input" id="encryptWalletPasswordConfirm" placeholder="Confirm password" style="padding-right: 50px;">
                            <button type="button" onclick="togglePasswordVisibility('encryptWalletPasswordConfirm', this)" style="position: absolute; right: 8px; top: 50%; transform: translateY(-50%); background: none; border: none; color: var(--text-muted); cursor: pointer; padding: 4px 8px; font-size: 0.85rem;">Show</button>
                        </div>
                    </div>
                    <button class="btn btn-primary" onclick="encryptNodeWallet()">🔒 Encrypt Wallet</button>
                </div>

                <!-- Encrypted -->
                <div id="nodeWalletEncrypted" style="display: none;">
                    <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 16px; padding: 12px; background: rgba(34, 197, 94, 0.1); border-radius: 8px;">
                        <span style="font-size: 1.2rem;">✅</span>
                        <div>
                            <div style="font-weight: 600; color: var(--success);">Wallet Encrypted</div>
                            <div style="font-size: 0.8rem; color: var(--text-muted);" id="nodeWalletLockStatus">Locked</div>
                        </div>
                    </div>

                    <!-- Change password section -->
                    <details style="margin-top: 16px;">
                        <summary style="cursor: pointer; color: var(--primary); font-weight: 500;">Change Password</summary>
                        <div style="padding: 16px 0;">
                            <div class="form-group">
                                <label class="form-label">Current Password</label>
                                <div style="position: relative;">
                                    <input type="password" class="form-input" id="oldNodePassword" placeholder="Current password" style="padding-right: 50px;">
                                    <button type="button" onclick="togglePasswordVisibility('oldNodePassword', this)" style="position: absolute; right: 8px; top: 50%; transform: translateY(-50%); background: none; border: none; color: var(--text-muted); cursor: pointer; padding: 4px 8px; font-size: 0.85rem;">Show</button>
                                </div>
                            </div>
                            <div class="form-group">
                                <label class="form-label">New Password (min 8 characters)</label>
                                <div style="position: relative;">
                                    <input type="password" class="form-input" id="newNodePassword" placeholder="New password" style="padding-right: 50px;">
                                    <button type="button" onclick="togglePasswordVisibility('newNodePassword', this)" style="position: absolute; right: 8px; top: 50%; transform: translateY(-50%); background: none; border: none; color: var(--text-muted); cursor: pointer; padding: 4px 8px; font-size: 0.85rem;">Show</button>
                                </div>
                            </div>
                            <div class="form-group">
                                <label class="form-label">Confirm New Password</label>
                                <div style="position: relative;">
                                    <input type="password" class="form-input" id="confirmNewNodePassword" placeholder="Confirm new password" style="padding-right: 50px;">
                                    <button type="button" onclick="togglePasswordVisibility('confirmNewNodePassword', this)" style="position: absolute; right: 8px; top: 50%; transform: translateY(-50%); background: none; border: none; color: var(--text-muted); cursor: pointer; padding: 4px 8px; font-size: 0.85rem;">Show</button>
                                </div>
                            </div>
                            <button class="btn btn-primary" onclick="changeNodeWalletPassword()">Change Password</button>
                            <p style="font-size: 0.8rem; color: var(--text-muted); margin-top: 12px;">
                                Forgot your current password? Stop the node, restart it, and choose <strong>Restore Wallet</strong> with your 24-word recovery phrase. This will create a new wallet file with a new password.
                            </p>
                        </div>
                    </details>
                </div>
            </div>

            <!-- Connection Mode Selector -->
            <div class="card" id="connectionModeCard">
                <div class="card-title">🌐 Connection Mode</div>
                <p style="color: var(--text-secondary); margin-bottom: 16px; font-size: 0.9rem;">
                    Choose how to connect to the Dilithion network. Your wallet works the same in both modes.
                </p>
                <div class="form-group">
                    <label class="form-label">Mode</label>
                    <select class="form-input" id="connectionMode" onchange="handleModeChange()">
                        <option value="full">Full Node (localhost) - Faster, private, can mine</option>
                        <option value="light">Light Mode (seed nodes) - No node required</option>
                    </select>
                </div>
                <div id="modeDescription" style="padding: 12px; border-radius: 8px; margin-top: 12px;">
                    <div id="fullModeDesc" style="background: rgba(34, 197, 94, 0.1); padding: 12px; border-radius: 8px;">
                        <strong style="color: #22c55e;">Full Node Mode</strong>
                        <p style="font-size: 0.85rem; color: var(--text-secondary); margin: 8px 0 0 0;">
                            Connect to your local Dilithion node for faster queries and mining support.
                            Your keys stay in the browser - the node only provides blockchain data.
                        </p>
                    </div>
                    <div id="lightModeDesc" style="display: none; background: rgba(200, 162, 78, 0.1); padding: 12px; border-radius: 8px;">
                        <strong style="color: #C8A24E;">Light Mode</strong>
                        <p style="font-size: 0.85rem; color: var(--text-secondary); margin: 8px 0 0 0;">
                            Connect to Dilithion seed nodes. No local node required.
                            Perfect for checking balance and sending DIL on the go.
                        </p>
                    </div>
                </div>
            </div>

            <!-- Create/Restore Light Wallet Modal -->
            <div id="lightWalletModal" style="display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.8); z-index: 1000; display: none; align-items: center; justify-content: center;">
                <div style="background: var(--bg-card); padding: 32px; border-radius: 16px; max-width: 500px; width: 90%; max-height: 90vh; overflow-y: auto;">
                    <!-- Create new wallet -->
                    <div id="createWalletForm">
                        <h3 style="margin-bottom: 16px;">Create New Light Wallet</h3>
                        <div class="form-group">
                            <label class="form-label">Password</label>
                            <input type="password" class="form-input" id="newLightPassword" placeholder="Minimum 8 characters">
                        </div>
                        <div class="form-group">
                            <label class="form-label">Confirm Password</label>
                            <input type="password" class="form-input" id="confirmLightPassword" placeholder="Re-enter password">
                        </div>
                        <div style="display: flex; gap: 12px;">
                            <button class="btn btn-primary" onclick="createLightWallet()">Create Wallet</button>
                            <button class="btn" onclick="closeLightWalletModal()">Cancel</button>
                        </div>
                    </div>

                    <!-- Restore wallet -->
                    <div id="restoreWalletForm" style="display: none;">
                        <h3 style="margin-bottom: 16px;">Restore from Mnemonic</h3>
                        <div class="form-group">
                            <label class="form-label">24-Word Mnemonic</label>
                            <textarea class="form-input" id="restoreMnemonic" rows="4"
                                      placeholder="Enter your 24 words separated by spaces"></textarea>
                        </div>
                        <div class="form-group">
                            <label class="form-label">Password</label>
                            <input type="password" class="form-input" id="restoreLightPassword" placeholder="Minimum 8 characters — encrypts your wallet">
                        </div>
                        <div style="display: flex; gap: 12px;">
                            <button class="btn btn-primary" onclick="restoreLightWallet()">Restore Wallet</button>
                            <button class="btn" onclick="closeLightWalletModal()">Cancel</button>
                        </div>
                    </div>

                    <!-- Show mnemonic (after creation) -->
                    <div id="showMnemonicForm" style="display: none;">
                        <h3 style="margin-bottom: 16px; color: var(--warning);">⚠️ Backup Your Recovery Phrase</h3>
                        <p style="color: var(--text-secondary); margin-bottom: 16px;">
                            Write down these 24 words in order. This is the ONLY way to recover your wallet if you lose access.
                        </p>
                        <div id="lightWalletMnemonicDisplay" style="background: var(--bg-darker); padding: 16px; border-radius: 8px; font-family: 'JetBrains Mono', monospace; margin-bottom: 16px;">
                        </div>
                        <div style="background: rgba(239, 68, 68, 0.1); padding: 12px; border-radius: 8px; margin-bottom: 16px;">
                            <strong style="color: #ef4444;">NEVER share these words with anyone!</strong>
                            <p style="font-size: 0.85rem; color: var(--text-secondary); margin: 4px 0 0 0;">
                                Anyone with these words can steal your funds.
                            </p>
                        </div>
                        <button class="btn btn-primary" onclick="confirmMnemonicBackup()">I've Written Them Down</button>
                    </div>
                </div>
            </div>

            <!-- LP-9: Blocking "Secure your wallet" migration modal.
                 Shown when a legacy UNENCRYPTED browser wallet is detected at load.
                 Has NO cancel/close button and no close-wiring (no Escape/backdrop-click
                 handler exists), so it cannot be dismissed; the wallet cannot be used until
                 the seed is encrypted at rest. Even if the element were hidden, the next
                 load re-presents it because the stored record is still encrypted:false. -->
            <div id="walletMigrationModal" style="display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.92); z-index: 2000; align-items: center; justify-content: center;">
                <div style="background: var(--bg-card); padding: 32px; border-radius: 16px; max-width: 480px; width: 90%; max-height: 90vh; overflow-y: auto;">
                    <h3 style="margin-bottom: 8px;">🔒 Secure your wallet</h3>
                    <p style="color: var(--text-secondary); margin-bottom: 16px; font-size: 0.9rem;">
                        Your wallet is currently stored <strong style="color: var(--error, #ef4444);">unencrypted</strong> in this browser, which means anyone with access to this device could read your recovery seed. Set a password now to encrypt it. This uses the <em>same wallet and the same addresses</em> — you do not need to re-enter your recovery phrase.
                    </p>
                    <div class="form-group">
                        <label class="form-label">New Password</label>
                        <input type="password" class="form-input" id="migrationPassword" placeholder="Minimum 8 characters">
                    </div>
                    <div class="form-group">
                        <label class="form-label">Confirm Password</label>
                        <input type="password" class="form-input" id="migrationPasswordConfirm" placeholder="Re-enter password">
                    </div>
                    <div id="migrationError" style="display:none; color: var(--error, #ef4444); font-size: 0.85rem; margin-bottom: 12px;"></div>
                    <button class="btn btn-primary" id="migrationSubmitBtn" onclick="submitWalletMigration()" style="width: 100%;">Encrypt &amp; Continue</button>
                    <p style="color: var(--text-muted); font-size: 0.75rem; margin-top: 12px; text-align: center;">
                        You must encrypt your wallet to continue.
                    </p>
                </div>
            </div>

            <div class="card" id="fullNodeSettingsCard">
                <div class="card-title">🔗 Node Connection</div>
                <p style="color: var(--text-secondary); margin-bottom: 16px; font-size: 0.9rem;">
                    Connect to your local Dilithion node. Your keys stay on your computer for maximum security.
                </p>
                <div class="form-group">
                    <label class="form-label">RPC Host</label>
                    <input type="text" class="form-input" id="rpcHost" value="127.0.0.1">
                </div>
                <div class="form-group">
                    <label class="form-label">RPC Port</label>
                    <input type="number" class="form-input" id="rpcPort" value="8332">
                    <small style="color: var(--text-muted); font-size: 0.75rem;">DIL: 8332, DilV: 9332, Testnet: 18332</small>
                </div>
                <div class="form-group">
                    <label class="form-label">RPC Username <small style="color: var(--text-muted); font-weight: normal;">(only if not served by your node)</small></label>
                    <input type="text" class="form-input" id="rpcUser" value="" placeholder="from dilithion.conf / .cookie" autocomplete="off">
                </div>
                <div class="form-group">
                    <label class="form-label">RPC Password</label>
                    <input type="password" class="form-input" id="rpcPass" value="" placeholder="from dilithion.conf / .cookie" autocomplete="off">
                </div>
                <button class="btn btn-primary" onclick="saveSettings()">Save & Connect</button>
            </div>

            <!-- Wallet Security Section -->
            <div class="card" id="securityCard">
                <div class="card-title">🔒 Wallet Security</div>

                <!-- Encryption Status -->
                <div id="encryptionStatus" style="margin-bottom: 16px;">
                    <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 12px;">
                        <span id="encryptionIcon" style="font-size: 1.5rem;">⏳</span>
                        <div>
                            <div id="encryptionLabel" style="font-weight: 600;">Checking encryption status...</div>
                            <div id="encryptionDesc" style="font-size: 0.8rem; color: var(--text-muted);">Please wait</div>
                        </div>
                    </div>
                </div>

                <!-- Encrypt Wallet (shown if not encrypted) -->
                <div id="encryptSection" style="display: none; border-top: 1px solid var(--border); padding-top: 16px; margin-top: 16px;">
                    <div style="background: rgba(239, 68, 68, 0.1); border-left: 3px solid #ef4444; padding: 12px; border-radius: 6px; margin-bottom: 16px;">
                        <strong style="color: #ef4444;">⚠️ Your wallet is NOT encrypted!</strong>
                        <p style="font-size: 0.85rem; color: var(--text-secondary); margin: 8px 0 0 0;">
                            Anyone with access to your computer can steal your funds. Encrypt your wallet now.
                        </p>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Create Wallet Password</label>
                        <input type="password" class="form-input" id="newWalletPassword" placeholder="Minimum 12 characters">
                        <small style="color: var(--text-muted); font-size: 0.75rem;">Use a strong, unique password. Mix letters, numbers, and symbols.</small>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Confirm Password</label>
                        <input type="password" class="form-input" id="confirmWalletPassword" placeholder="Re-enter password">
                    </div>
                    <button class="btn btn-primary" onclick="encryptWallet()" style="background: linear-gradient(135deg, #22c55e 0%, #16a34a 100%);">
                        🔐 Encrypt Wallet Now
                    </button>
                </div>

                <!-- Lock/Unlock (shown if encrypted) -->
                <div id="lockSection" style="display: none; border-top: 1px solid var(--border); padding-top: 16px; margin-top: 16px;">
                    <div id="lockStatus" style="display: flex; align-items: center; gap: 8px; margin-bottom: 12px;">
                        <span id="lockIcon" style="font-size: 1.2rem;">🔒</span>
                        <span id="lockLabel">Wallet is locked</span>
                    </div>

                    <!-- Unlock Form -->
                    <div id="unlockForm">
                        <div class="form-group">
                            <label class="form-label">Wallet Password</label>
                            <input type="password" class="form-input" id="unlockPassword" placeholder="Enter your wallet password">
                        </div>
                        <div class="form-group">
                            <label class="form-label">Unlock Duration (seconds)</label>
                            <input type="number" class="form-input" id="unlockDuration" value="300" min="1" max="3600">
                            <small style="color: var(--text-muted); font-size: 0.75rem;">Wallet will auto-lock after this time</small>
                        </div>
                        <button class="btn btn-primary" onclick="unlockWallet()">🔓 Unlock Wallet</button>
                    </div>

                    <!-- Lock Button (shown when unlocked) -->
                    <div id="lockForm" style="display: none;">
                        <button class="btn" onclick="lockWallet()" style="background: var(--bg-secondary);">🔒 Lock Wallet Now</button>
                    </div>
                </div>

                <!-- Security Tips -->
                <div style="border-top: 1px solid var(--border); padding-top: 16px; margin-top: 16px;">
                    <div style="font-size: 0.85rem; color: var(--text-muted);">
                        <strong>Security Tips:</strong>
                        <ul style="margin: 8px 0 0 16px; padding: 0;">
                            <li>Write down your 24-word recovery phrase on paper</li>
                            <li>Never share your password or recovery phrase</li>
                            <li>Lock your wallet when not in use</li>
                        </ul>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-title">Connection Help</div>
                <p style="color: var(--text-secondary); margin-bottom: 12px;">
                    This wallet connects to your local Dilithion node via RPC.
                </p>
                <p style="font-size: 0.875rem; color: var(--text-muted); margin-bottom: 8px;">
                    <strong>To start your node:</strong>
                </p>
                <code style="display: block; background: var(--bg-darker); padding: 12px; border-radius: 6px; font-size: 0.8rem; color: var(--accent); margin-bottom: 12px; overflow-x: auto;">
                    # Mainnet<br>
                    dilithion-node --port=8444 --rpcport=8332<br><br>
                    # Testnet<br>
                    dilithion-node --testnet --port=18444 --rpcport=18332
                </code>
                <p style="font-size: 0.875rem; color: var(--text-muted);">
                    The wallet will automatically connect once the node is running.
                </p>
            </div>

            <div class="card">
                <div class="card-title">About</div>
                <p style="color: var(--text-secondary); margin-bottom: 12px;">
                    Dilithion Web Wallet v1.0.0<br>
                    Post-quantum secure cryptocurrency
                </p>
            </div>
        </div>
        <!-- Bridge Page -->
        <div class="page" id="page-bridge">
            <div class="page-header">
                <h1 class="page-title">Bridge</h1>
                <p class="page-subtitle">Convert between native coins and wrapped tokens on Base</p>
            </div>

            <!-- MetaMask Connection -->
            <div class="card" style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px;">
                <div>
                    <div class="card-title" style="margin-bottom: 4px;">MetaMask</div>
                    <p style="color: var(--text-secondary); margin: 0; font-size: 0.85rem;" id="bridgeMetaMaskStatus">Not connected</p>
                </div>
                <button class="btn btn-primary" id="bridgeConnectBtn" onclick="bridgeConnectWallet()">Connect MetaMask</button>
            </div>

            <!-- Bridge Sub-tabs -->
            <div style="display: flex; gap: 4px; margin-bottom: 20px; background: var(--bg-darker); border-radius: 10px; padding: 4px;">
                <div class="bridge-tab active" data-bridge-tab="deposit" onclick="switchBridgeTab('deposit')" style="flex: 1; text-align: center; padding: 10px; border-radius: 8px; cursor: pointer; font-size: 0.85rem; font-weight: 500; color: var(--text-secondary); transition: all 0.2s;">Deposit (to Base)</div>
                <div class="bridge-tab" data-bridge-tab="withdraw" onclick="switchBridgeTab('withdraw')" style="flex: 1; text-align: center; padding: 10px; border-radius: 8px; cursor: pointer; font-size: 0.85rem; font-weight: 500; color: var(--text-secondary); transition: all 0.2s;">Withdraw (from Base)</div>
            </div>

            <!-- DEPOSIT PANEL -->
            <div id="bridge-deposit-panel">
                <!-- Quick Buy -->
                <div class="card" style="border-color: var(--primary); background: rgba(200,162,78,0.04);">
                    <div class="card-title">Just want to buy?</div>
                    <p style="color: var(--text-secondary); font-size: 0.85rem; margin-bottom: 12px;">
                        The easiest way is to buy directly on Aerodrome using ETH. No bridging needed.
                    </p>
                    <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                        <a href="https://aerodrome.finance/swap?outputCurrency=0x30629128d1d3524F1A01B9c385FbE84fDCbD36C2" target="_blank" class="btn btn-primary" style="text-decoration: none; font-size: 0.8rem;">Buy wDIL</a>
                        <a href="https://aerodrome.finance/swap?outputCurrency=0xF162F6B432FeeD73458D4653ef8E74Ba014403E8" target="_blank" class="btn" style="text-decoration: none; font-size: 0.8rem; border: 1px solid var(--primary); color: var(--primary);">Buy wDILV</a>
                    </div>
                </div>

                <!-- Bridge Deposit Form -->
                <div class="card">
                    <div class="card-title">Bridge: <span class="chain-label">DIL</span> to Base</div>
                    <div id="bridgeHttpsWarning" style="display: none; background: #161614; border: 1px solid #B08A3E; border-radius: 8px; padding: 10px 14px; margin-bottom: 12px; font-size: 0.8rem; color: #E8C860; line-height: 1.5;">
                        <strong>Deposits require your local node.</strong> Open
                        <a href="http://127.0.0.1:8332/" style="color: #E8C860; text-decoration: underline;">http://127.0.0.1:8332/</a>
                        in your browser and use the Bridge tab there. Withdrawals work here via MetaMask.
                    </div>
                    <p style="color: var(--text-secondary); font-size: 0.85rem; margin-bottom: 16px;">
                        Send native coins to the bridge address with your MetaMask address tagged in OP_RETURN. Your node must be running.
                    </p>

                    <!-- Chain toggle -->
                    <div style="display: flex; gap: 4px; margin-bottom: 16px; background: var(--bg-darker); border-radius: 8px; padding: 3px;">
                        <div class="bridge-chain-opt active" onclick="bridgeSelectDepositChain('dil')" style="flex:1; text-align:center; padding:8px; border-radius:6px; cursor:pointer; font-size:0.8rem; font-weight:500; transition:all 0.2s;">DIL to wDIL</div>
                        <div class="bridge-chain-opt" onclick="bridgeSelectDepositChain('dilv')" style="flex:1; text-align:center; padding:8px; border-radius:6px; cursor:pointer; font-size:0.8rem; font-weight:500; color:var(--text-muted); transition:all 0.2s;">DilV to wDILV</div>
                    </div>

                    <div class="form-group">
                        <label class="form-label">Your MetaMask address (on Base)</label>
                        <input type="text" class="form-input" id="bridgeDepositBaseAddr" placeholder="0x..." oninput="bridgeValidateDeposit()">
                    </div>

                    <div class="form-group">
                        <label class="form-label">Amount of <span id="bridgeDepositCoinLabel">DIL</span> to bridge</label>
                        <input type="number" class="form-input" id="bridgeDepositAmount" placeholder="100" step="0.01" oninput="bridgeValidateDeposit()">
                        <small style="color: var(--text-muted); font-size: 0.75rem;" id="bridgeDepositLimitNote">Max per deposit: 500 DIL. Daily limit: 1,000 DIL.</small>
                    </div>

                    <button class="btn btn-primary" id="bridgeDepositBtn" onclick="bridgeExecuteDeposit()" disabled style="width: 100%; padding: 12px;">
                        Enter details above
                    </button>

                    <div id="bridgeDepositStatus" style="margin-top: 12px; max-height: 200px; overflow-y: auto; display: none;"></div>

                    <div style="margin-top: 12px; padding: 10px 12px; background: var(--bg-darker); border-radius: 8px; font-size: 0.8rem; color: var(--text-muted); line-height: 1.5;">
                        After <strong id="bridgeConfirmCount">6</strong> confirmations (<strong id="bridgeConfirmTime">~24 min</strong>),
                        <strong id="bridgeWrappedLabel">wDIL</strong> will be minted to your MetaMask wallet.
                    </div>
                </div>

                <!-- Add to MetaMask -->
                <div class="card">
                    <div class="card-title">See tokens in MetaMask</div>
                    <p style="color: var(--text-secondary); font-size: 0.85rem; margin-bottom: 8px;">Import token in MetaMask with this contract address:</p>
                    <div style="background: var(--bg-darker); border: 1px solid var(--border); border-radius: 8px; padding: 10px 14px; font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; word-break: break-all; color: var(--accent); cursor: pointer;" id="bridgeTokenContract" onclick="navigator.clipboard.writeText(this.textContent).then(()=>{showNotification('Copied!','success')})">0x30629128d1d3524F1A01B9c385FbE84fDCbD36C2</div>
                </div>
            </div>

            <!-- WITHDRAW PANEL -->
            <div id="bridge-withdraw-panel" style="display: none;">
                <div class="card">
                    <div class="card-title">Withdraw: Wrapped tokens back to native</div>
                    <p style="color: var(--text-secondary); font-size: 0.85rem; margin-bottom: 16px;">
                        Burns wDIL/wDILV on Base and the bridge sends native coins to your wallet. Requires MetaMask on Base network.
                    </p>

                    <!-- Chain toggle -->
                    <div style="display: flex; gap: 4px; margin-bottom: 16px; background: var(--bg-darker); border-radius: 8px; padding: 3px;">
                        <div class="bridge-wchain-opt active" onclick="bridgeSelectWithdrawChain('dil')" style="flex:1; text-align:center; padding:8px; border-radius:6px; cursor:pointer; font-size:0.8rem; font-weight:500; transition:all 0.2s;">wDIL to DIL</div>
                        <div class="bridge-wchain-opt" onclick="bridgeSelectWithdrawChain('dilv')" style="flex:1; text-align:center; padding:8px; border-radius:6px; cursor:pointer; font-size:0.8rem; font-weight:500; color:var(--text-muted); transition:all 0.2s;">wDILV to DilV</div>
                    </div>

                    <div class="form-group">
                        <label class="form-label">Amount to withdraw</label>
                        <input type="number" class="form-input" id="bridgeWithdrawAmount" placeholder="0.00" step="0.00000001">
                    </div>

                    <div class="form-group">
                        <label class="form-label">Your Dilithion wallet address (starts with D)</label>
                        <input type="text" class="form-input" id="bridgeWithdrawNativeAddr" placeholder="DJrywx4AsVQSPLZCKRdg8erZdPMNaRSrKq">
                    </div>

                    <button class="btn btn-primary" id="bridgeWithdrawBtn" onclick="bridgeExecuteBurn()" disabled style="width: 100%; padding: 12px;">
                        Connect MetaMask First
                    </button>

                    <div id="bridgeWithdrawResult" style="margin-top: 12px; display: none;"></div>
                </div>
            </div>

            <!-- Bridge Info -->
            <div class="card">
                <div class="card-title">Bridge Info</div>
                <div style="font-size: 0.8rem; color: var(--text-secondary); line-height: 2;">
                    <div style="display: flex; justify-content: space-between;"><span>wDIL Contract</span><span style="font-family: 'JetBrains Mono', monospace; color: var(--accent); font-size: 0.7rem;">0x3062...D36C2</span></div>
                    <div style="display: flex; justify-content: space-between;"><span>wDILV Contract</span><span style="font-family: 'JetBrains Mono', monospace; color: var(--accent); font-size: 0.7rem;">0xF162...03E8</span></div>
                    <div style="display: flex; justify-content: space-between;"><span>DIL Bridge Address</span><span style="font-family: 'JetBrains Mono', monospace; color: var(--accent); font-size: 0.7rem;">DNaTbw...6cinx</span></div>
                    <div style="display: flex; justify-content: space-between;"><span>DilV Bridge Address</span><span style="font-family: 'JetBrains Mono', monospace; color: var(--accent); font-size: 0.7rem;">DTHGN3...BuPdp</span></div>
                </div>
                <p style="color: var(--text-muted); font-size: 0.75rem; margin-top: 8px;">
                    Custodial bridge. Will be upgraded to 3-of-5 multisig when value at stake justifies it.
                </p>
            </div>
        </div>

    </main>

    <script>
        // Auto-fit balance text — shrinks font only when it overflows the card
        // Quick unlock from dashboard prompt
        // Lock wallet and show welcome screen (allows switching to a different wallet)
        function lockAndSwitch() {
            if (localWallet) {
                localWallet.lock();
            }
            updateLightWalletUI();
            // Reset balances
            document.getElementById('totalBalance').textContent = '---';
            document.getElementById('matureBalance').textContent = '---';
            document.getElementById('immatureBalance').textContent = '---';
            // Show welcome screen
            document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
            document.getElementById('page-welcome').style.display = 'block';
            document.getElementById('page-welcome').classList.add('active');
            showNotification('Wallet locked. Import a different wallet or unlock the current one.', 'info');
        }

        async function dashboardQuickUnlock() {
            const pw = document.getElementById('dashboardUnlockPw').value;
            if (!pw) return;
            try {
                await localWallet.unlock(pw);
                document.getElementById('dashboardUnlockPw').value = '';
                document.getElementById('dashboardUnlockPrompt').style.display = 'none';
                showNotification('Wallet unlocked', 'success');
                updateLightWalletUI();
                refreshAll();
            } catch (e) {
                if (e && e.message === 'WALLET_NEEDS_ENCRYPTION') {
                    presentWalletMigration();
                    return;
                }
                showNotification('Wrong password', 'error');
            }
        }

        function fitBalanceText() {
            document.querySelectorAll('.balance-amount').forEach(el => {
                el.style.fontSize = '';  // reset to CSS default (2rem)
                let size = 2;
                while (el.scrollWidth > el.clientWidth && size > 0.8) {
                    size -= 0.1;
                    el.style.fontSize = size + 'rem';
                }
            });
        }

        // Wallet State
        let connected = false;
        let rpcConfig = {
            host: '127.0.0.1',
            port: 8332,  // Mainnet RPC port (testnet: 18332)
            user: '',    // wallet-rpc-login-restore: no guessable default (was 'rpc')
            pass: ''     // populated only via manual override when not served by a node
        };

        // wallet-rpc-login-restore: same-origin RPC session token.
        // When this page is served BY a Dilithion node, the node injects a fresh
        // server-validated token into the <meta name="dilithion-rpc-token"> tag.
        // We use it as the RPC credential (Authorization: Basic __token__:<tok>)
        // INSTEAD of a username/password. This is the supported same-origin login
        // path on a default node — no credential paste required. The token is
        // held in memory only (never localStorage) and re-read on each call so a
        // freshly-served page always uses the latest minted token.
        function getSessionToken() {
            const m = document.querySelector('meta[name="dilithion-rpc-token"]');
            if (!m) return '';
            const v = (m.getAttribute('content') || '').trim();
            // The literal sentinel means the page was NOT served by a node
            // (opened from disk) — no token available, fall back to manual creds.
            if (!v || v === '__DILITHION_RPC_SESSION_TOKEN__') return '';
            return v;
        }

        // Active chain: 'dil' or 'dilv'
        let activeChain = 'dil';  // Always start on DIL
        let chainSwitchGen = 0;   // Generation counter to discard stale async responses
        let chainPorts = { dil: 8332, dilv: 9332 };
        try {
            const savedPorts = JSON.parse(localStorage.getItem('dilithionChainPorts') || 'null');
            if (savedPorts && Number.isInteger(savedPorts.dil) && Number.isInteger(savedPorts.dilv)) {
                chainPorts = savedPorts;
            }
        } catch(e) {}
        const chainUnits = { dil: 'DIL', dilv: 'DilV' };

        // dilv-node-wallet-csp-origin: When this page is served BY a node, its
        // own origin (host:port) IS that node's RPC endpoint, and the served
        // page's CSP `connect-src 'self'` means it can ONLY fetch its own
        // origin. The DIL node serves on :8332, the DilV node on :9332 — two
        // different origins. So the chain/port MUST be derived from the serving
        // origin, not the hardcoded DIL default; otherwise the DilV node's
        // wallet (:9332) boots pointed at :8332 and every request is CSP-blocked
        // ("Connection failed"). Returns null for opened-from-disk (file:) and
        // for the remotely-hosted wallet (https, no port) so those paths keep
        // their existing cross-origin / light-mode behaviour untouched.
        // dilv-node-wallet-csp-origin: the node injects its chain ("dil"/"dilv")
        // into the dilithion-chain meta when it serves the page; '' if opened
        // from disk or the sentinel survived (not node-served). This is the node's
        // authoritative answer and is preferred over guessing from the RPC port.
        function getServedChainHint() {
            const m = document.querySelector('meta[name="dilithion-chain"]');
            if (!m) return '';
            const v = (m.getAttribute('content') || '').trim();
            return (v === 'dil' || v === 'dilv') ? v : '';
        }
        function detectServedOrigin() {
            const loc = window.location;
            const isLoopback = loc.hostname === '127.0.0.1' || loc.hostname === 'localhost';
            if (loc.protocol !== 'http:' || !isLoopback || !loc.port) return null;
            const port = parseInt(loc.port, 10);
            const chainHint = getServedChainHint();
            const knownNodePort = (port === chainPorts.dil || port === chainPorts.dilv ||
                port === 8332 || port === 9332 || port === 18332 || port === 19332);
            // Treat as node-served when it's a recognised node RPC port, or the
            // page carries a node-injected session token / chain hint — avoids
            // hijacking an unrelated local dev server on loopback while still
            // covering a node running on a custom --rpcport.
            if (!knownNodePort && !getSessionToken() && !chainHint) return null;
            // Chain identity: trust the node's authoritative hint when present;
            // otherwise map the origin port (DilV = 9332 / 19332 / a custom
            // chainPorts.dilv; everything else is DIL).
            const chain = chainHint ||
                ((port === chainPorts.dilv || port === 9332 || port === 19332) ? 'dilv' : 'dil');
            return { host: loc.hostname, port: port, chain: chain };
        }
        const servedOrigin = detectServedOrigin();
        if (servedOrigin) {
            // The serving origin is authoritative for a node-served page.
            activeChain = servedOrigin.chain;
            rpcConfig.host = servedOrigin.host;
            rpcConfig.port = servedOrigin.port;
            chainPorts[servedOrigin.chain] = servedOrigin.port;
        }

        function switchChain(chain) {
            if (chain === activeChain) return;
            // dilv-node-wallet-csp-origin: on a node-served page each chain lives
            // at a different origin (DIL :8332 / DilV :9332) and CSP
            // `connect-src 'self'` forbids reaching the other port from this
            // page. So switching chains here means NAVIGATING to the sibling
            // node's own wallet page (which boots on its chain via
            // detectServedOrigin), not an in-page cross-origin fetch the browser
            // would block. Requires that sibling node to be running.
            if (servedOrigin) {
                const targetPort = chainPorts[chain] || (chain === 'dilv' ? 9332 : 8332);
                // Defence-in-depth: targetPort derives from chainPorts (localStorage-
                // sourced), so range-check it before using it as a navigation sink.
                // Host is always this page's own loopback hostname, so navigation
                // can only ever target another loopback port — never a remote origin.
                if (Number.isInteger(targetPort) && targetPort > 0 && targetPort <= 65535 &&
                    targetPort !== servedOrigin.port) {
                    window.location.href = window.location.protocol + '//' +
                        window.location.hostname + ':' + targetPort + '/';
                    return;
                }
            }
            activeChain = chain;
            const myGen = ++chainSwitchGen;  // Capture generation for stale detection
            localStorage.setItem('dilithionActiveChain', chain);

            // Update toggle buttons
            const btnDil = document.getElementById('chainBtnDil');
            const btnDilv = document.getElementById('chainBtnDilv');
            if (chain === 'dil') {
                btnDil.style.background = 'var(--primary)';
                btnDil.style.color = 'white';
                btnDilv.style.background = 'transparent';
                btnDilv.style.color = 'var(--text-muted)';
            } else {
                btnDilv.style.background = 'var(--secondary)';
                btnDilv.style.color = 'white';
                btnDil.style.background = 'transparent';
                btnDil.style.color = 'var(--text-muted)';
            }

            // Update all balance unit labels and chain labels
            document.querySelectorAll('.balance-unit, .chain-label').forEach(el => {
                el.textContent = chainUnits[chain];
            });

            // Update page title
            document.title = chain === 'dil' ? 'Dilithion Web Wallet' : 'DilV Web Wallet';

            // Switch RPC port and reconnect
            rpcConfig.port = chainPorts[chain];
            document.getElementById('rpcPort').value = rpcConfig.port;
            // wallet-rpc-login-restore: persist host/port ONLY — never credentials.
            localStorage.setItem('dilithionWalletConfig', JSON.stringify({
                host: rpcConfig.host, port: rpcConfig.port
            }));
            // Update chain ID for transaction signing (DIL=1, DilV=2)
            if (txBuilder) txBuilder.chainId = chain === 'dilv' ? 2 : 1;
            // Update connection manager chain for API routing
            if (connectionManager) connectionManager.setChain(chain);
            // Update ALL mobile chain buttons (More menu + dashboard toggle)
            const chainBtns = [
                ['mChainDil', 'mChainDilv'],
                ['mobileChainDil', 'mobileChainDilv']
            ];
            for (const [dilId, dilvId] of chainBtns) {
                const d = document.getElementById(dilId);
                const v = document.getElementById(dilvId);
                if (d && v) {
                    if (chain === 'dil') {
                        d.style.background = 'var(--primary)'; d.style.color = 'white'; d.style.border = 'none';
                        v.style.background = 'transparent'; v.style.color = 'var(--text-muted)'; v.style.border = '1px solid var(--border)';
                    } else {
                        v.style.background = 'var(--secondary)'; v.style.color = 'white'; v.style.border = 'none';
                        d.style.background = 'transparent'; d.style.color = 'var(--text-muted)'; d.style.border = '1px solid var(--border)';
                    }
                }
            }

            // Clear ALL stale data immediately and show loading state
            document.getElementById('totalBalance').textContent = '...';
            document.getElementById('matureBalance').textContent = '...';
            document.getElementById('immatureBalance').textContent = '...';
            document.getElementById('availableForSend').textContent = '...';
            document.getElementById('blockHeight').textContent = '-';
            document.getElementById('recentTxList').innerHTML = '<div class="empty-state">Switching to ' + chainUnits[chain] + '...</div>';
            const txListEl = document.getElementById('txList');
            if (txListEl) txListEl.innerHTML = '';

            // Show loading overlay
            showChainSwitchOverlay(chain);

            // Reconnect with new chain (async, guarded by generation counter)
            (async () => {
                try {
                    const isLightMode = connectionManager && connectionManager.getMode() === 'light';
                    if (isLightMode) {
                        await connectionManager.connect();
                        if (chainSwitchGen !== myGen) return;  // Stale — user switched again
                        setConnectionStatus(true, (chain === 'dilv' ? 'DilV' : 'DIL') + ' Light Wallet');
                        await refreshAll();
                    } else {
                        await connect();
                        if (chainSwitchGen !== myGen) return;  // Stale
                        await refreshAll();
                    }
                } catch (e) {
                    if (chainSwitchGen !== myGen) return;  // Stale
                    setConnectionStatus(false, 'Connection failed');
                    document.getElementById('totalBalance').textContent = '0.00000000';
                    document.getElementById('matureBalance').textContent = '0.00000000';
                    document.getElementById('immatureBalance').textContent = '0.00000000';
                    document.getElementById('availableForSend').textContent = '0.00000000';
                } finally {
                    if (chainSwitchGen === myGen) {
                        hideChainSwitchOverlay();
                    }
                }
            })();
        }

        function showChainSwitchOverlay(chain) {
            let overlay = document.getElementById('chainSwitchOverlay');
            if (!overlay) {
                overlay = document.createElement('div');
                overlay.id = 'chainSwitchOverlay';
                document.body.appendChild(overlay);
            }
            overlay.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.6);display:flex;align-items:center;justify-content:center;z-index:99999;';
            overlay.innerHTML = '<div style="background:#1a1a18;padding:32px 48px;border-radius:12px;text-align:center;box-shadow:0 8px 32px rgba(0,0,0,0.6);border:1px solid rgba(200,162,78,0.3);">' +
                '<div style="width:36px;height:36px;border:3px solid rgba(200,162,78,0.3);border-top-color:#C8A24E;border-radius:50%;animation:spin 0.8s linear infinite;margin:0 auto 16px;"></div>' +
                '<div style="font-weight:600;font-size:1.1rem;color:#E8D5A0;">Switching to ' + chainUnits[chain] + '</div>' +
                '<div style="color:#8a8a80;font-size:0.85rem;margin-top:8px;">Loading wallet data...</div>' +
                '</div>';
        }

        function hideChainSwitchOverlay() {
            const overlay = document.getElementById('chainSwitchOverlay');
            if (overlay) {
                overlay.remove();
            }
        }

        // Initialize chain toggle on load
        function initChainSelector() {
            // Apply saved chain state
            if (activeChain === 'dilv') {
                // Sidebar buttons
                const btnDil = document.getElementById('chainBtnDil');
                const btnDilv = document.getElementById('chainBtnDilv');
                if (btnDilv) { btnDilv.style.background = 'var(--secondary)'; btnDilv.style.color = 'white'; }
                if (btnDil) { btnDil.style.background = 'transparent'; btnDil.style.color = 'var(--text-muted)'; }

                // Mobile dashboard toggle
                const mDil = document.getElementById('mobileChainDil');
                const mDilv = document.getElementById('mobileChainDilv');
                if (mDilv) { mDilv.style.background = 'var(--secondary)'; mDilv.style.color = 'white'; mDilv.style.border = 'none'; }
                if (mDil) { mDil.style.background = 'transparent'; mDil.style.color = 'var(--text-muted)'; mDil.style.border = '1px solid var(--border)'; }

                // Mobile More menu toggle
                const mmDil = document.getElementById('mChainDil');
                const mmDilv = document.getElementById('mChainDilv');
                if (mmDilv) { mmDilv.style.background = 'var(--secondary)'; mmDilv.style.color = 'white'; mmDilv.style.border = 'none'; }
                if (mmDil) { mmDil.style.background = 'transparent'; mmDil.style.color = 'var(--text-muted)'; mmDil.style.border = '1px solid var(--border)'; }

                // Labels and title
                document.querySelectorAll('.balance-unit, .chain-label').forEach(el => {
                    el.textContent = 'DilV';
                });
                document.title = 'DilV Web Wallet';
                // dilv-node-wallet-csp-origin: use the resolved DilV port (a
                // node-served page already set this from its origin; a custom
                // chainPorts.dilv is honoured) instead of hardcoding 9332.
                rpcConfig.port = chainPorts.dilv || 9332;

                // Update connection manager chain
                if (connectionManager) connectionManager.setChain('dilv');
                if (txBuilder) txBuilder.chainId = 2;
            }
        }

        // Load saved settings
        // wallet-rpc-login-restore: only host/port are persisted. RPC credentials
        // are NEVER written to localStorage (MED-1): on a node-served page the
        // session token supplies auth; for a from-disk page the user re-enters
        // manual creds each session (in-memory only).
        function loadSettings() {
            // dilv-node-wallet-csp-origin: a node-served page MUST talk to its
            // own origin (CSP connect-src 'self'); never let a stale saved
            // host/port pull it cross-origin. The origin was already applied
            // above — here we just sync the Settings inputs and skip the
            // localStorage host/port override entirely.
            if (servedOrigin) {
                rpcConfig.host = servedOrigin.host;
                rpcConfig.port = servedOrigin.port;
                const hostEl = document.getElementById('rpcHost');
                const portEl = document.getElementById('rpcPort');
                if (hostEl) hostEl.value = rpcConfig.host;
                if (portEl) portEl.value = rpcConfig.port;
                return;
            }
            const saved = localStorage.getItem('dilithionWalletConfig');
            if (saved) {
                try {
                    const savedCfg = JSON.parse(saved);
                    rpcConfig.host = savedCfg.host || rpcConfig.host;
                    rpcConfig.port = savedCfg.port || rpcConfig.port;
                    // Prefer per-chain port for current activeChain over the last-saved port
                    if (chainPorts[activeChain]) rpcConfig.port = chainPorts[activeChain];
                    document.getElementById('rpcHost').value = rpcConfig.host;
                    document.getElementById('rpcPort').value = rpcConfig.port;
                    // Do NOT restore user/pass from storage — no guessable defaults.
                } catch(e) {}
            }
        }

        // Save settings
        function saveSettings() {
            rpcConfig.host = document.getElementById('rpcHost').value;
            rpcConfig.port = parseInt(document.getElementById('rpcPort').value);
            // Manual-override credentials are kept in memory only (not persisted).
            rpcConfig.user = document.getElementById('rpcUser').value;
            rpcConfig.pass = document.getElementById('rpcPass').value;
            chainPorts[activeChain] = rpcConfig.port;
            localStorage.setItem('dilithionChainPorts', JSON.stringify(chainPorts));
            // wallet-rpc-login-restore: persist host/port ONLY — never credentials.
            localStorage.setItem('dilithionWalletConfig', JSON.stringify({
                host: rpcConfig.host, port: rpcConfig.port
            }));
            showNotification('Settings saved. Connecting...', 'info');
            connect();
        }

        // RPC call mutex to prevent parallel requests
        let rpcMutex = Promise.resolve();
        let consecutiveErrors = 0;
        const MAX_CONSECUTIVE_ERRORS = 3;  // Only disconnect after 3 consecutive failures

        // RPC Call with timeout and mutex
        async function rpcCall(method, params = [], timeoutMs = 10000) {
            // Wait for any pending RPC call to complete
            const previousCall = rpcMutex;
            let resolveThis;
            rpcMutex = new Promise(r => resolveThis = r);
            await previousCall;

            try {
                const result = await rpcCallInternal(method, params, timeoutMs);
                consecutiveErrors = 0;  // Reset on success
                return result;
            } catch (e) {
                // Track consecutive errors
                if (e.message && (e.message.includes('fetch') || e.message.includes('timed out'))) {
                    consecutiveErrors++;
                    console.warn('[RPC] Connection error count:', consecutiveErrors);
                    if (consecutiveErrors >= MAX_CONSECUTIVE_ERRORS) {
                        setConnectionStatus(false, 'Connection lost');
                        consecutiveErrors = 0;  // Reset after disconnect
                    }
                }
                throw e;
            } finally {
                // Small delay before allowing next call
                setTimeout(resolveThis, 100);
            }
        }

        // Internal RPC call implementation
        async function rpcCallInternal(method, params = [], timeoutMs = 10000) {
            const url = `http://${rpcConfig.host}:${rpcConfig.port}/`;
            const headers = {
                'Content-Type': 'application/json',
                'X-Dilithion-RPC': '1'  // Required for CSRF protection (presence-only)
            };

            // wallet-rpc-login-restore: prefer the node-injected same-origin
            // session token. It is a REAL server-validated credential — the node
            // maps "__token__:<token>" to the configured cookie/rpcuser creds and
            // runs the existing auth + permissions path. Falls back to manual
            // rpcuser/rpcpassword only when the page was not served by a node.
            const sessionToken = getSessionToken();
            if (sessionToken) {
                headers['Authorization'] = 'Basic ' + btoa('__token__:' + sessionToken);
            } else if (rpcConfig.user && rpcConfig.pass) {
                headers['Authorization'] = 'Basic ' + btoa(rpcConfig.user + ':' + rpcConfig.pass);
            }

            // Retry logic with exponential backoff for connection errors
            const maxRetries = 3;
            let lastError = null;

            for (let attempt = 0; attempt < maxRetries; attempt++) {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

                try {
                    const response = await fetch(url, {
                        method: 'POST',
                        headers: headers,
                        signal: controller.signal,
                        body: JSON.stringify({
                            jsonrpc: '2.0',
                            id: Date.now(),
                            method: method,
                            params: params
                        })
                    });
                    clearTimeout(timeoutId);

                    const data = await response.json();
                    if (data.error) {
                        console.error('[RPC] Error for', method, ':', JSON.stringify(data.error));
                        // Handle different error formats
                        let errMsg = 'RPC Error';
                        if (typeof data.error === 'string') {
                            errMsg = data.error;
                        } else if (data.error.message) {
                            errMsg = data.error.message;
                        } else if (data.error.code) {
                            errMsg = 'RPC Error (code: ' + data.error.code + ')';
                        }
                        throw new Error(errMsg);
                    }
                    return data.result;
                } catch (e) {
                    clearTimeout(timeoutId);
                    lastError = e;

                    // Don't retry on timeout or RPC errors, only connection errors
                    if (e.name === 'AbortError') {
                        throw new Error('Request timed out');
                    }
                    if (e.message && !e.message.includes('fetch')) {
                        throw e;  // RPC error, don't retry
                    }

                    // Wait before retry (exponential backoff: 100ms, 200ms, 400ms)
                    if (attempt < maxRetries - 1) {
                        await new Promise(r => setTimeout(r, 100 * Math.pow(2, attempt)));
                    }
                }
            }
            throw lastError || new Error('Connection failed after retries');
        }

        // Update connection status
        function setConnectionStatus(isConnected, text) {
            connected = isConnected;
            const dot = document.getElementById('statusDot');
            const statusText = document.getElementById('statusText');
            const reconnectBtn = document.getElementById('reconnectBtn');

            if (isConnected) {
                dot.classList.add('connected');
                statusText.textContent = text || 'Connected';
                if (reconnectBtn) reconnectBtn.style.display = 'none';
            } else {
                dot.classList.remove('connected');
                statusText.textContent = text || 'Disconnected';
                // Show reconnect button when disconnected (but not during initial connecting)
                if (reconnectBtn && text !== 'Connecting...') {
                    reconnectBtn.style.display = 'block';
                }
            }
        }

        // Show toast notification
        function showNotification(message, type = 'info') {
            // Remove any existing notification
            const existing = document.getElementById('toast-notification');
            if (existing) existing.remove();

            // Create notification element
            const toast = document.createElement('div');
            toast.id = 'toast-notification';
            toast.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                padding: 16px 24px;
                border-radius: 8px;
                color: white;
                font-weight: 500;
                z-index: 10000;
                animation: slideIn 0.3s ease-out;
                max-width: 400px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            `;

            // Set background color based on type
            switch (type) {
                case 'success':
                    toast.style.background = 'linear-gradient(135deg, #22c55e 0%, #16a34a 100%)';
                    break;
                case 'error':
                    toast.style.background = 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)';
                    break;
                case 'warning':
                    toast.style.background = 'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)';
                    break;
                default:
                    toast.style.background = 'linear-gradient(135deg, #C8A24E 0%, #B08A3E 100%)';
            }

            toast.textContent = message;
            document.body.appendChild(toast);

            // Auto-remove after 5 seconds (longer for errors)
            const duration = type === 'error' ? 7000 : 5000;
            setTimeout(() => {
                toast.style.animation = 'slideOut 0.3s ease-in';
                setTimeout(() => toast.remove(), 300);
            }, duration);
        }

        // Add animation styles for notifications
        const notificationStyles = document.createElement('style');
        notificationStyles.textContent = `
            @keyframes slideIn {
                from { transform: translateX(100%); opacity: 0; }
                to { transform: translateX(0); opacity: 1; }
            }
            @keyframes slideOut {
                from { transform: translateX(0); opacity: 1; }
                to { transform: translateX(100%); opacity: 0; }
            }
        `;
        document.head.appendChild(notificationStyles);

        // Toggle password visibility
        function togglePasswordVisibility(inputId, button) {
            const input = document.getElementById(inputId);
            if (input.type === 'password') {
                input.type = 'text';
                button.textContent = 'Hide';
            } else {
                input.type = 'password';
                button.textContent = 'Show';
            }
        }

        // Connect to node
        async function connect() {
            setConnectionStatus(false, 'Connecting...');
            console.log('[Connect] Attempting connection to', rpcConfig.host + ':' + rpcConfig.port);
            try {
                const info = await rpcCall('getblockchaininfo');
                console.log('[Connect] Connection successful, chain:', info.chain);
                const networkLabel = info.chain === 'testnet' ? 'Testnet' : 'Mainnet';
                const chainLabel = activeChain === 'dilv' ? 'DilV' : 'DIL';
                setConnectionStatus(true, chainLabel + ' ' + networkLabel);

                // Wait before making more requests - server needs time between connections
                console.log('[Connect] Waiting 1 second before loading data...');
                await new Promise(r => setTimeout(r, 1000));

                // MINIMAL initial load - just get balance + check encryption
                console.log('[Connect] Loading initial balance...');
                await refreshBalance();
                await updateDashboardEncryptionBanner();
                console.log('[Connect] Initial load complete');

            } catch(e) {
                setConnectionStatus(false, 'Connection failed');
                console.error('[Connect] Connection failed:', e.message);
                console.log('[Connect] Tried to connect to:', rpcConfig.host + ':' + rpcConfig.port);

                // Clear stale data from previous chain
                document.getElementById('totalBalance').textContent = '0.00000000';
                document.getElementById('matureBalance').textContent = '0.00000000';
                document.getElementById('immatureBalance').textContent = '0.00000000';
                document.getElementById('availableForSend').textContent = '0.00000000';
                document.getElementById('recentTxList').innerHTML =
                    '<div class="empty-state">Unable to connect to ' + chainUnits[activeChain] + ' node on port ' + rpcConfig.port + '</div>';
                const txListEl = document.getElementById('txList');
                if (txListEl) txListEl.innerHTML = '';
                fitBalanceText();
            }
        }

        // Auto-configure mining to send rewards to browser wallet address
        async function autoSetMiningAddress() {
            // Only in full node mode
            if (connectionManager && connectionManager.getMode() === 'light') {
                return;  // Light mode doesn't need this
            }

            // Check if browser wallet is unlocked
            if (!localWallet || !localWallet.isWalletUnlocked()) {
                console.log('[Mining] Browser wallet not unlocked, skipping auto mining address');
                return;
            }

            try {
                // Get first address from browser wallet
                const addresses = await localWallet.getAddresses();
                if (!addresses || addresses.length === 0) {
                    console.log('[Mining] No addresses in browser wallet');
                    return;
                }

                const myAddress = addresses[0].address;

                // Check if already set
                try {
                    const current = await rpcCall('getminingaddress');
                    if (current.address === myAddress) {
                        console.log('[Mining] Mining address already set to:', myAddress);
                        return;
                    }
                } catch (e) {
                    // getminingaddress might not exist on older nodes
                }

                // Set mining address via RPC
                await rpcCall('setminingaddress', [myAddress]);
                console.log('[Mining] Auto-set mining address to:', myAddress);
                showNotification('Mining rewards will go to your wallet', 'success');
            } catch (e) {
                console.warn('[Mining] Failed to auto-set mining address:', e.message);
                // Don't show error - node might not support this RPC yet
            }
        }

        // Refresh all data (serialized to prevent connection overload)
        // --- Mining Stats Page ---
        async function refreshMiningStats() {
            if (!connected) return;
            const isLightMode = connectionManager && connectionManager.getMode() === 'light';
            const HASHES_PER_DIFF = Math.pow(2, 32) / 393216;

            // Network overview (works in both modes via getblockchaininfo)
            // Chain-specific params: DIL = 50/block, 210K halving, 240s blocks; DilV = 100/block, 1.05M halving, 45s blocks
            const chainRewardParams = {
                dil:  { baseReward: 50, halvingInterval: 210000, blockTime: 240 },
                dilv: { baseReward: 100, halvingInterval: 1050000, blockTime: 45 }
            };
            const rewardParams = chainRewardParams[activeChain] || chainRewardParams.dil;
            try {
                const info = await rpcCall('getblockchaininfo');
                const difficulty = info.difficulty || 0;
                const height = info.blocks || 0;
                const halvings = Math.floor(height / rewardParams.halvingInterval);
                const reward = rewardParams.baseReward / Math.pow(2, halvings);
                const networkHashrate = difficulty * HASHES_PER_DIFF / rewardParams.blockTime;

                document.getElementById('msNetworkHashrate').textContent = formatMsHashrate(networkHashrate);
                document.getElementById('msDifficulty').textContent = difficulty.toLocaleString();
                const unit = chainUnits[activeChain];
                document.getElementById('msBlockReward').textContent = reward + ' ' + unit + ' (' + (reward * 0.98).toFixed(2) + ' to miner)';
            } catch (e) {
                console.error('[MiningStats] Chain info error:', e);
            }

            if (isLightMode) {
                document.getElementById('msUniqueMiners').textContent = 'Full node required';
                document.getElementById('msDfmpContent').innerHTML =
                    '<p style="color:var(--text-muted);">Connect to your local node (Full Node mode in Settings) to view DFMP data and miner distribution.</p>';
                document.getElementById('msDistributionContent').innerHTML =
                    '<p style="color:var(--text-muted);">Connect to your local node (Full Node mode in Settings) to view miner distribution.</p>';
                return;
            }

            // MIK Distribution (RPC only)
            try {
                const dist = await rpcCall('getmikdistribution');
                document.getElementById('msUniqueMiners').textContent = (dist.unique_miners || 0).toString();

                const miners = dist.distribution || [];
                miners.sort((a, b) => b.blocks - a.blocks);
                const topMiners = miners.slice(0, 20);
                const totalBlocks = miners.reduce((s, m) => s + m.blocks, 0);

                let html = '';

                // Bar chart visualization
                if (topMiners.length > 0) {
                    const maxBlocks = topMiners[0].blocks;
                    html += '<div style="margin-bottom:20px;">';
                    topMiners.slice(0, 10).forEach((m, i) => {
                        const pct = maxBlocks > 0 ? (m.blocks / maxBlocks * 100).toFixed(0) : 0;
                        const share = totalBlocks > 0 ? (m.blocks / totalBlocks * 100).toFixed(1) : '0';
                        const shortMik = m.mik.substring(0, 8) + '...' + m.mik.substring(m.mik.length - 6);
                        html += '<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">';
                        html += '<span style="min-width:28px;font-size:0.75rem;color:var(--text-muted);text-align:right;">#' + (i+1) + '</span>';
                        html += '<span style="min-width:120px;font-size:0.75rem;font-family:\'JetBrains Mono\',monospace;color:var(--text-secondary);">' + shortMik + '</span>';
                        html += '<div style="flex:1;height:18px;background:var(--bg-darker);border-radius:4px;overflow:hidden;">';
                        html += '<div style="width:' + pct + '%;height:100%;background:linear-gradient(90deg,var(--primary),var(--secondary));border-radius:4px;transition:width 0.3s;"></div>';
                        html += '</div>';
                        html += '<span style="min-width:60px;font-size:0.8rem;font-family:\'JetBrains Mono\',monospace;text-align:right;">' + m.blocks + ' <span style="color:var(--text-muted);font-size:0.7rem;">(' + share + '%)</span></span>';
                        html += '</div>';
                    });
                    html += '</div>';
                }

                // Summary
                html += '<div style="padding:12px;background:var(--bg-darker);border-radius:8px;font-size:0.85rem;color:var(--text-secondary);">';
                html += '<strong>' + miners.length + '</strong> unique miners in the current ' + (dist.window_size || 360) + '-block window. ';
                html += 'Total <strong>' + totalBlocks + '</strong> blocks tracked.';
                html += '</div>';

                document.getElementById('msDistributionContent').innerHTML = html;
            } catch (e) {
                document.getElementById('msUniqueMiners').textContent = 'Error';
                document.getElementById('msDistributionContent').innerHTML =
                    '<p style="color:var(--error);">Failed to load: ' + e.message + '</p>';
            }

            // DFMP Info (RPC only)
            try {
                const dfmp = await rpcCall('getdfmpinfo');
                let html = '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:16px;">';

                html += '<div class="info-item"><span class="info-label" style="color:#8A8A80;font-size:12px;">DFMP Version</span>';
                html += '<span class="info-value">' + (dfmp.dfmp_v3_active ? 'v3.1' : (dfmp.dfmp_active ? 'v2.0' : 'Inactive')) + '</span></div>';

                html += '<div class="info-item"><span class="info-label" style="color:#8A8A80;font-size:12px;">Your MIK Registered</span>';
                html += '<span class="info-value">' + (dfmp.is_registered ? 'Yes' : 'No') + '</span></div>';

                html += '<div class="info-item"><span class="info-label" style="color:#8A8A80;font-size:12px;">Heat Level</span>';
                const heatColor = (dfmp.heat || 0) > 10 ? 'var(--warning)' : 'var(--success)';
                html += '<span class="info-value" style="color:' + heatColor + ';">' + (dfmp.heat || 0) + ' blocks</span></div>';

                html += '<div class="info-item"><span class="info-label" style="color:#8A8A80;font-size:12px;">Maturity Penalty</span>';
                html += '<span class="info-value">' + (dfmp.maturity_penalty || '1.00') + 'x</span></div>';

                html += '<div class="info-item"><span class="info-label" style="color:#8A8A80;font-size:12px;">Heat Penalty</span>';
                html += '<span class="info-value">' + (dfmp.effective_heat_penalty || '1.00') + 'x</span></div>';

                const totalPenalty = dfmp.total_penalty || 1.0;
                const penaltyColor = totalPenalty > 2.0 ? 'var(--error)' : (totalPenalty > 1.0 ? 'var(--warning)' : 'var(--success)');
                html += '<div class="info-item"><span class="info-label" style="color:#8A8A80;font-size:12px;">Total Difficulty Multiplier</span>';
                html += '<span class="info-value" style="color:' + penaltyColor + ';">' + totalPenalty + 'x</span></div>';

                html += '</div>';

                // Explanation
                html += '<div style="padding:12px;background:var(--bg-darker);border-radius:8px;font-size:0.85rem;color:var(--text-secondary);line-height:1.6;">';
                html += '<strong style="color:var(--text-primary);">How DFMP works:</strong> The Dynamic Fair Mining Protocol increases difficulty for miners who mine too many blocks in a window (high heat), ';
                html += 'ensuring fair distribution. New miners have a maturity penalty that decays over ~400 blocks. ';
                html += 'A <strong>1.00x</strong> multiplier = no penalty (best). Higher = harder to mine.';
                html += '</div>';

                document.getElementById('msDfmpContent').innerHTML = html;
            } catch (e) {
                document.getElementById('msDfmpContent').innerHTML =
                    '<p style="color:var(--error);">Failed to load DFMP info: ' + e.message + '</p>';
            }
        }

        function formatMsHashrate(h) {
            if (h >= 1e12) return (h / 1e12).toFixed(2) + ' TH/s';
            if (h >= 1e9) return (h / 1e9).toFixed(2) + ' GH/s';
            if (h >= 1e6) return (h / 1e6).toFixed(2) + ' MH/s';
            if (h >= 1e3) return (h / 1e3).toFixed(2) + ' KH/s';
            return h.toFixed(0) + ' H/s';
        }

        async function refreshAll() {
            const isLightConnected = connectionManager && connectionManager.isConnected();
            if (!connected && !isLightConnected) return;
            const wait = () => new Promise(r => setTimeout(r, 300));  // 300ms between function calls
            try {
                // Serialize requests with delays to prevent server socket issues
                await refreshBalance();
                await wait();
                await refreshBlockchainInfo();
                await wait();
                await refreshTransactions();
                // Refresh mining stats if that page is active
                const msPage = document.getElementById('page-mining-stats');
                if (msPage && msPage.classList.contains('active')) {
                    await wait();
                    await refreshMiningStats();
                }
            } catch(e) {
                console.error('Refresh error:', e);
            }
        }

        // Refresh balance
        async function refreshBalance() {
            const balanceGen = chainSwitchGen;  // Capture for stale detection
            try {
                const isFullNode = !connectionManager || connectionManager.getMode() === 'full';

                if (isFullNode && connected) {
                    // FULL NODE MODE: Get balance directly from node's wallet via RPC
                    console.log('[Balance] Calling getbalance RPC...');
                    try {
                        const nodeBalance = await rpcCall('getbalance');
                        if (chainSwitchGen !== balanceGen) return;  // Stale — chain switched during request
                        console.log('[Balance] Success:', nodeBalance);
                        const mature = nodeBalance.balance || 0;
                        const unconfirmed = nodeBalance.unconfirmed_balance || 0;
                        const immature = nodeBalance.immature_balance || 0;
                        const total = mature + unconfirmed + immature;

                        document.getElementById('totalBalance').textContent = total.toFixed(8);
                        document.getElementById('matureBalance').textContent = mature.toFixed(8);
                        document.getElementById('immatureBalance').textContent = immature.toFixed(8);
                        document.getElementById('availableForSend').textContent = mature.toFixed(8);
                        fitBalanceText();

                        // Chain health warning
                        const chainHealth = nodeBalance.chain_health || 'OK';
                        const warningEl = document.getElementById('chainWarning');
                        if (chainHealth === 'DIVERGED') {
                            warningEl.style.display = 'block';
                            warningEl.textContent = nodeBalance.chain_warning || 'Your chain tip differs from the network. Mined coins may not be valid on the main chain.';
                        } else {
                            warningEl.style.display = 'none';
                        }
                        // Check if wallet needs UTXO optimization
                        checkUtxoHealth();
                    } catch (e) {
                        console.error('[Balance] RPC error:', e.message);
                        // Connection loss is handled centrally in rpcCall()
                    }
                } else if (!isFullNode) {
                    // LIGHT WALLET MODE: Use browser wallet addresses
                    const unlockPrompt = document.getElementById('dashboardUnlockPrompt');
                    if (!localWallet || !localWallet.isWalletUnlocked()) {
                        document.getElementById('totalBalance').textContent = '---';
                        document.getElementById('matureBalance').textContent = '---';
                        document.getElementById('immatureBalance').textContent = '---';
                        document.getElementById('availableForSend').textContent = '0.00000000';
                        if (unlockPrompt) unlockPrompt.style.display = 'block';
                        const lockBtnHide = document.getElementById('lockWalletBtn');
                        if (lockBtnHide) lockBtnHide.style.display = 'none';
                        return;
                    }
                    if (unlockPrompt) unlockPrompt.style.display = 'none';
                    const lockBtn = document.getElementById('lockWalletBtn');
                    if (lockBtn) lockBtn.style.display = 'block';

                    const addresses = await localWallet.getAddresses();
                    if (chainSwitchGen !== balanceGen) return;  // Stale
                    let confirmedBalance = 0;
                    let unconfirmedBalance = 0;

                    for (const addr of addresses) {
                        try {
                            const balanceInfo = await connectionManager.getBalance(addr.address);
                            if (chainSwitchGen !== balanceGen) return;  // Stale
                            confirmedBalance += (balanceInfo.confirmed || 0) / 100000000;
                            unconfirmedBalance += (balanceInfo.unconfirmed || 0) / 100000000;
                        } catch (e) {
                            console.warn('[Balance] Failed to get balance for', addr.address, e.message);
                        }
                    }

                    const total = confirmedBalance + unconfirmedBalance;
                    document.getElementById('totalBalance').textContent = total.toFixed(8);
                    document.getElementById('matureBalance').textContent = confirmedBalance.toFixed(8);
                    document.getElementById('immatureBalance').textContent = '0.00000000';
                    document.getElementById('availableForSend').textContent = confirmedBalance.toFixed(8);
                    fitBalanceText();
                } else {
                    // Not connected
                    document.getElementById('totalBalance').textContent = '0.00000000';
                    document.getElementById('matureBalance').textContent = '0.00000000';
                    document.getElementById('immatureBalance').textContent = '0.00000000';
                    document.getElementById('availableForSend').textContent = '0.00000000';
                }
            } catch(e) {
                console.error('Balance error:', e);
            }
        }

        // Refresh blockchain info
        async function refreshBlockchainInfo() {
            const infoGen = chainSwitchGen;  // Capture for stale detection
            const wait = () => new Promise(r => setTimeout(r, 300));  // 300ms delay between calls

            // Check if we're in light wallet mode
            const isLightMode = connectionManager && connectionManager.getMode() === 'light';

            try {
                let info;
                if (isLightMode) {
                    // Light wallet mode: use REST API via connectionManager
                    info = await connectionManager.getBlockchainInfo();
                } else {
                    // Full node mode: use RPC
                    info = await rpcCall('getblockchaininfo');
                }
                if (chainSwitchGen !== infoGen) return;  // Stale — chain switched during request

                document.getElementById('networkName').textContent = info.chain || 'Unknown';
                document.getElementById('blockHeight').textContent = info.blocks?.toLocaleString() || info.height?.toLocaleString() || '-';
                document.getElementById('bestBlock').textContent = info.bestblockhash || '-';
                document.getElementById('difficulty').textContent = info.difficulty?.toFixed(6) || '-';

                if (!isLightMode) {
                    await wait();  // Delay before next RPC call

                    // Peer info (full node only)
                    try {
                        const peers = await rpcCall('getpeerinfo');
                        const inbound = peers.filter(p => p.inbound).length;
                        const outbound = peers.filter(p => !p.inbound).length;
                        document.getElementById('peerCount').textContent = peers.length;
                        document.getElementById('inboundPeers').textContent = inbound;
                        document.getElementById('outboundPeers').textContent = outbound;
                    } catch(e) {
                        document.getElementById('peerCount').textContent = '-';
                    }

                    await wait();  // Delay before next RPC call

                    // Mining info (full node only)
                    try {
                        const mining = await rpcCall('getmininginfo');
                        document.getElementById('miningActive').textContent = mining.mining ? 'Yes' : 'No';
                        document.getElementById('hashRate').textContent = mining.hashrate ?
                            mining.hashrate.toFixed(2) + ' H/s' : '-';

                        // Update dashboard mining card
                        updateMiningDashboard(mining, info.difficulty);
                    } catch(e) {
                        document.getElementById('miningActive').textContent = '-';
                        document.getElementById('hashRate').textContent = '-';
                    }
                } else {
                    // Light mode: show N/A for node-specific info
                    document.getElementById('peerCount').textContent = 'N/A';
                    document.getElementById('inboundPeers').textContent = '-';
                    document.getElementById('outboundPeers').textContent = '-';
                    document.getElementById('miningActive').textContent = 'N/A';
                    document.getElementById('hashRate').textContent = '-';
                }
            } catch(e) {
                console.error('Blockchain info error:', e);
                // Connection loss is handled centrally in rpcCall()
            }
        }

        // Track blocks found - counts actual mining rewards (49 DILI coinbase transactions)
        let totalBlocksMined = 0;
        let lastBlockHeight = 0;
        let isMiningActive = false;

        // Update mining dashboard card
        function updateMiningDashboard(miningInfo, difficulty) {
            const miningActive = miningInfo.mining || false;
            const hashrate = miningInfo.hashrate || 0;

            // Update status
            isMiningActive = miningActive;
            const statusDot = document.getElementById('miningStatusDot');
            const statusText = document.getElementById('miningStatus');
            const btnText = document.getElementById('miningBtnText');
            const btn = document.getElementById('miningToggle');

            if (miningActive) {
                statusDot.style.background = '#22c55e';  // Green
                statusText.textContent = 'Mining';
                btnText.textContent = 'Stop Mining';
                btn.classList.remove('btn-primary');
                btn.classList.add('btn-secondary');
            } else {
                statusDot.style.background = '#666';  // Gray
                statusText.textContent = 'Stopped';
                btnText.textContent = 'Start Mining';
                btn.classList.remove('btn-secondary');
                btn.classList.add('btn-primary');
            }

            // Update hash rate
            const hashRateEl = document.getElementById('dashHashRate');
            if (hashrate >= 1000000) {
                hashRateEl.textContent = (hashrate / 1000000).toFixed(2) + ' MH/s';
            } else if (hashrate >= 1000) {
                hashRateEl.textContent = (hashrate / 1000).toFixed(2) + ' KH/s';
            } else {
                hashRateEl.textContent = hashrate.toFixed(2) + ' H/s';
            }

            // Both counters reset on node process start.
            //  submitted = blocks this miner has VDF-solved and broadcast.
            //  accepted  = blocks on the canonical chain mined by our MIK (mirrors reorgs).
            // Gap is expected: DilV uses lowest-VDF-output-wins distribution, so
            // competing miners' lower outputs cause our submitted blocks to be
            // reorged out. DFMP per-MIK fair-share caps also limit acceptance.
            const submitted = miningInfo.blocks_found || 0;
            const accepted = miningInfo.blocks_accepted || 0;
            const blocksEl = document.getElementById('blocksFound');
            if (submitted > 0 && submitted !== accepted) {
                blocksEl.innerHTML = '<span style="color:#C8B560;">' + accepted + '</span>' +
                    ' <span style="color:#8A8A80;font-size:11px;">accepted &middot; ' +
                    submitted + ' submitted</span>';
            } else {
                blocksEl.textContent = accepted;
            }

            // Calculate estimated time to block
            const etaEl = document.getElementById('etaToBlock');
            if (!miningActive || hashrate <= 0) {
                etaEl.textContent = 'N/A';
            } else {
                etaEl.textContent = estimateTimeToBlock(hashrate, difficulty);
            }

            // Fetch and display mining address
            refreshMiningAddress();
        }

        // Fetch the current mining address and display it in the dashboard
        async function refreshMiningAddress() {
            const row = document.getElementById('miningAddressRow');
            const textEl = document.getElementById('miningAddressText');
            try {
                const result = await rpcCall('getminingaddress');
                if (result && result.address) {
                    textEl.textContent = result.address;
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            } catch (e) {
                row.style.display = 'none';
            }
        }

        // Copy the mining address to clipboard
        function copyMiningAddress() {
            const addr = document.getElementById('miningAddressText').textContent;
            if (!addr || addr === '—') return;
            navigator.clipboard.writeText(addr).then(() => {
                showNotification('Mining address copied', 'success');
            }).catch(() => {
                // Fallback for older browsers
                const ta = document.createElement('textarea');
                ta.value = addr;
                document.body.appendChild(ta);
                ta.select();
                document.execCommand('copy');
                document.body.removeChild(ta);
                showNotification('Mining address copied', 'success');
            });
        }

        // Estimate time to find next block
        function estimateTimeToBlock(hashrate, difficulty) {
            if (!hashrate || hashrate <= 0 || !difficulty) return 'N/A';

            // Dilithion max target: 0x1f060000 → mantissa 0x060000 = 393216
            // expectedHashes = difficulty * (2^32 / maxMantissa)
            // At difficulty 1.0, you need ~10,923 hashes on average
            const HASHES_PER_DIFFICULTY = Math.pow(2, 32) / 393216;
            const expectedHashes = difficulty * HASHES_PER_DIFFICULTY;
            const secondsToBlock = expectedHashes / hashrate;

            if (secondsToBlock < 60) return '< 1 min';
            if (secondsToBlock < 3600) return '~' + Math.round(secondsToBlock / 60) + ' min';
            if (secondsToBlock < 86400) return '~' + (secondsToBlock / 3600).toFixed(1) + ' hrs';
            return '~' + (secondsToBlock / 86400).toFixed(1) + ' days';
        }

        // Handle thread selector change
        function handleThreadChange() {
            const select = document.getElementById('miningThreads');
            const customInput = document.getElementById('customThreads');

            if (select.value === 'custom') {
                customInput.style.display = 'inline-block';
                customInput.focus();
            } else {
                customInput.style.display = 'none';
            }
        }

        // Get selected thread count
        function getSelectedThreads() {
            const select = document.getElementById('miningThreads');
            const customInput = document.getElementById('customThreads');

            if (select.value === 'max') {
                // Use all available CPU cores
                return navigator.hardwareConcurrency || 4;
            } else if (select.value === 'custom') {
                const custom = parseInt(customInput.value);
                return (custom > 0 && custom <= 256) ? custom : 4;
            } else {
                return parseInt(select.value) || 4;
            }
        }

        // Toggle mining on/off
        async function toggleMining() {
            const btn = document.getElementById('miningToggle');
            const btnText = document.getElementById('miningBtnText');
            btn.disabled = true;

            try {
                if (isMiningActive) {
                    // Stop mining
                    btnText.textContent = 'Stopping...';
                    await rpcCall('stopmining');
                } else {
                    // Start mining with selected threads
                    const threads = getSelectedThreads();
                    btnText.textContent = 'Starting...';
                    console.log('[Mining] Starting with', threads, 'threads');
                    await rpcCall('startmining', { threads: threads });
                }
                // Refresh to get new status
                await refreshBlockchainInfo();
            } catch(e) {
                console.error('Mining toggle error:', e);
                alert('Failed to toggle mining: ' + e.message);
            } finally {
                btn.disabled = false;
            }
        }

        // Rescan wallet for missing transactions (clears old data first for chain resets)
        async function rescanWallet() {
            const btnText = document.getElementById('rescanBtnText');
            const originalText = btnText.textContent;
            const isLightMode = connectionManager && connectionManager.getMode() === 'light';

            if (isLightMode) {
                // Light mode: re-scan HD addresses via API and refresh balances
                btnText.textContent = 'Scanning...';
                try {
                    if (localWallet && localWallet.isWalletUnlocked() && connectionManager.isConnected()) {
                        const result = await localWallet.scanHDAddresses(connectionManager, (index, found) => {
                            btnText.textContent = `Scanning (${index})...`;
                        });
                        btnText.textContent = `Found ${result.found} addresses`;
                    }
                    await refreshBalance();
                    await refreshTransactions();
                    setTimeout(() => { btnText.textContent = originalText; }, 2000);
                } catch(e) {
                    console.error('Rescan error:', e);
                    btnText.textContent = 'Failed';
                    setTimeout(() => { btnText.textContent = originalText; }, 2000);
                }
            } else {
                // Full node mode: use RPC
                btnText.textContent = 'Clearing...';
                try {
                    await rpcCall('clearwallettxs', {});
                    btnText.textContent = 'Scanning...';
                    const result = await rpcCall('rescanwallet', {}, 120000);
                    btnText.textContent = 'Done!';
                    console.log('[Wallet] Rescan result:', result);
                    await refreshBalance();
                    await refreshTransactions();
                    setTimeout(() => { btnText.textContent = originalText; }, 2000);
                } catch(e) {
                    console.error('Rescan error:', e);
                    btnText.textContent = 'Failed';
                    setTimeout(() => { btnText.textContent = originalText; }, 2000);
                }
            }
        }

        // Check UTXO count and show optimization banner if needed
        async function checkUtxoHealth() {
            const isFullNode = !connectionManager || connectionManager.getMode() === 'full';
            const banner = document.getElementById('optimizeBanner');
            if (!banner || !isFullNode || !connected) return;
            try {
                const utxos = await rpcCall('listunspent');
                const count = Array.isArray(utxos) ? utxos.length : 0;
                if (count > 20) {
                    document.getElementById('optimizeUtxoCount').textContent =
                        'You currently have ' + count + ' separate payments to combine.';
                    banner.style.display = 'block';
                } else {
                    banner.style.display = 'none';
                }
            } catch(e) {
                banner.style.display = 'none';
            }
        }

        async function optimizeWallet() {
            const btn = document.getElementById('optimizeBtn');
            const originalText = btn.textContent;
            btn.textContent = 'Optimizing...';
            btn.disabled = true;
            try {
                const result = await rpcCall('consolidateutxos', {max_inputs: 50}, 60000);
                btn.textContent = 'Done! Combined ' + (result.inputs_consolidated || '?') + ' payments';
                await refreshBalance();
                // Check if more consolidation needed
                setTimeout(async () => {
                    await checkUtxoHealth();
                    btn.textContent = originalText;
                    btn.disabled = false;
                }, 3000);
            } catch(e) {
                const msg = e.message || String(e);
                if (msg.includes('locked')) {
                    btn.textContent = 'Unlock wallet first';
                } else if (msg.includes('Nothing to consolidate')) {
                    btn.textContent = 'Already optimized!';
                    document.getElementById('optimizeBanner').style.display = 'none';
                } else {
                    btn.textContent = 'Failed — try again';
                    console.error('[Optimize]', msg);
                }
                setTimeout(() => { btn.textContent = originalText; btn.disabled = false; }, 3000);
            }
        }

        // BUG #113 FIX: Refresh transactions using listtransactions for complete history
        // BUG #116 FIX: Don't overwrite existing transactions on refresh failure
        // BUG #117 FIX: Keep showing "Loading..." during initial connection
        let lastTransactions = null;  // Cache last successful transaction load
        let txLoadAttempts = 0;       // Track load attempts
        async function refreshTransactions() {
            const txGen = chainSwitchGen;  // Capture for stale detection
            const isFullNode = !connectionManager || connectionManager.getMode() === 'full';

            if (isFullNode && connected) {
                // FULL NODE MODE: Get transactions directly from node's wallet via RPC
                try {
                    const result = await rpcCall('listtransactions', {count: 50});
                    if (chainSwitchGen !== txGen) return;  // Stale
                    const transactions = result.transactions || [];

                    if (transactions.length > 0) {
                        renderTransactions(transactions);
                    } else {
                        const emptyHtml = '<div class="empty-state">No transactions yet</div>';
                        document.getElementById('recentTxList').innerHTML = emptyHtml;
                        const txListEl = document.getElementById('txList');
                        if (txListEl) txListEl.innerHTML = emptyHtml;
                    }
                } catch (e) {
                    console.error('[Transactions] RPC error:', e.message);
                    // Connection loss is handled centrally in rpcCall()
                }
            } else if (!isFullNode) {
                // LIGHT WALLET MODE: Show message (no TX history in browser)
                const browserWalletMessage = `
                    <div class="empty-state" style="text-align: center; padding: 24px;">
                        <div style="font-size: 2rem; margin-bottom: 12px;">🔐</div>
                        <div style="font-weight: 600; margin-bottom: 8px;">Light Wallet Mode</div>
                        <div style="color: var(--text-muted); font-size: 0.9rem;">
                            Your keys are stored securely in your browser.<br>
                            Use a block explorer to view transaction history.
                        </div>
                    </div>
                `;
                document.getElementById('recentTxList').innerHTML = browserWalletMessage;
                const txListEl = document.getElementById('txList');
                if (txListEl) txListEl.innerHTML = browserWalletMessage;

            }
        }

        // Format timestamp for display - shows both relative and absolute time
        function formatTimestamp(unixTime) {
            if (!unixTime) return 'Pending';
            const date = new Date(unixTime * 1000);
            const now = new Date();
            const diffMs = now - date;
            const diffMins = Math.floor(diffMs / 60000);
            const diffHours = Math.floor(diffMs / 3600000);
            const diffDays = Math.floor(diffMs / 86400000);

            // Format the absolute time
            const timeStr = date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
            const dateStr = date.toLocaleDateString([], {month: 'short', day: 'numeric'});

            // Combine relative and absolute
            let relative;
            if (diffMins < 1) relative = 'Just now';
            else if (diffMins < 60) relative = `${diffMins}m ago`;
            else if (diffHours < 24) relative = `${diffHours}h ago`;
            else if (diffDays < 7) relative = `${diffDays}d ago`;
            else relative = null;

            if (relative) {
                return `${relative} • ${dateStr} ${timeStr}`;
            }
            return `${dateStr} ${timeStr}`;
        }

        // Get full timestamp for tooltip
        function getFullTimestamp(unixTime) {
            if (!unixTime) return '';
            const date = new Date(unixTime * 1000);
            return date.toLocaleString();
        }

        // Address labeling
        const addressLabels = JSON.parse(localStorage.getItem('dilithionAddressLabels') || '{}');

        function getAddressLabel(address) {
            if (!address) return '';
            return addressLabels[address] || '';
        }

        function getAddressDisplay(address) {
            if (!address) return 'Unknown';
            const label = getAddressLabel(address);
            if (label) return label;
            return address.substring(0, 12) + '...';
        }

        function saveAddressLabel(address, label) {
            if (label && label.trim()) {
                addressLabels[address] = label.trim();
            } else {
                delete addressLabels[address];
            }
            localStorage.setItem('dilithionAddressLabels', JSON.stringify(addressLabels));
        }

        // BUG #113 FIX: Render transaction list with full history support
        function renderTransactions(transactions) {
            if (!transactions || transactions.length === 0) {
                const html = '<div class="empty-state">No transactions yet</div>';
                document.getElementById('recentTxList').innerHTML = html;
                document.getElementById('txList').innerHTML = html;
                return;
            }

            let html = '';
            transactions.slice(0, 50).forEach(tx => {
                const confirmations = tx.confirmations || 0;
                const amount = tx.amount || 0;
                const txid = tx.txid || 'unknown';
                const category = tx.category || 'receive';
                const isSend = category === 'send';
                const isMining = category === 'generate' || category === 'immature';
                const isSpent = category === 'spent';
                const fee = tx.fee || 0;
                const timestamp = tx.time || tx.blocktime || 0;
                const address = tx.address || '';

                // Determine origin type and icon
                let iconClass, typeText, originLabel, iconSvg;
                const addressDisplay = getAddressDisplay(address);
                if (isMining) {
                    iconClass = 'mining';
                    typeText = 'Mining Reward';
                    originLabel = 'Block Subsidy';
                    iconSvg = '<circle cx="12" cy="12" r="10"></circle><path d="M12 6v6l4 2"></path>';
                } else if (isSend) {
                    iconClass = 'sent';
                    typeText = 'Sent';
                    originLabel = address ? `To: ${addressDisplay}` : 'Transaction';
                    iconSvg = '<polyline points="22 2 15 22 11 13 2 9 22 2"></polyline>';
                } else if (isSpent) {
                    iconClass = 'spent';
                    typeText = 'Received (Spent)';
                    originLabel = address ? `To: ${addressDisplay}` : 'Transaction';
                    iconSvg = '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline>';
                } else {
                    iconClass = 'received';
                    typeText = 'Received';
                    originLabel = address ? `To: ${addressDisplay}` : 'Transaction';
                    iconSvg = '<polyline points="22 12 16 12 14 15 10 15 8 12 2 12"></polyline>';
                }

                const amountClass = isSend ? 'negative' : 'positive';
                const amountPrefix = isSend ? '' : '+';
                const displayAmount = Math.abs(amount).toFixed(8);
                const feeText = isSend && fee > 0 ? ` (fee: ${fee.toFixed(4)})` : '';
                const timeText = formatTimestamp(timestamp);
                const fullTimestamp = getFullTimestamp(timestamp);

                html += `
                    <div class="tx-item">
                        <div class="tx-icon ${iconClass}">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                ${iconSvg}
                            </svg>
                        </div>
                        <div class="tx-details">
                            <div class="tx-type">${typeText} <span style="color:#8A8A80;font-size:12px;" title="${fullTimestamp}">${timeText}</span></div>
                            <div class="tx-hash" style="font-size:11px;color:#5A5A52;" title="${address || ''}">${originLabel}</div>
                            <div class="tx-hash" title="${txid}" style="cursor:pointer;" onclick="navigator.clipboard.writeText('${txid}').then(()=>{const el=this;el.dataset.orig=el.textContent;el.textContent='Copied!';setTimeout(()=>el.textContent=el.dataset.orig,1500)})">${txid.substring(0, 16)}...${txid.substring(txid.length - 8)}</div>
                        </div>
                        <div>
                            <div class="tx-amount ${amountClass}">${amountPrefix}${displayAmount} ${chainUnits[activeChain]}${feeText}</div>
                            <div class="tx-confirmations">${confirmations} confirmations</div>
                        </div>
                    </div>
                `;
            });

            document.getElementById('recentTxList').innerHTML = html;
            document.getElementById('txList').innerHTML = html;
        }

        // Get receive address
        async function refreshReceiveAddress() {
            try {
                const isFullNode = !connectionManager || connectionManager.getMode() === 'full';
                let address;

                if (isFullNode && connected) {
                    // FULL NODE MODE: Get address directly from node's wallet via RPC
                    console.log('[Receive] Full node mode, calling getaddresses RPC');
                    try {
                        const addresses = await rpcCall('getaddresses');
                        if (addresses && addresses.length > 0) {
                            address = addresses[0];
                        } else {
                            // No addresses yet, generate one
                            address = await rpcCall('getnewaddress');
                        }
                    } catch (e) {
                        console.error('[Receive] RPC error:', e.message);
                        // Display error (connection loss is handled centrally in rpcCall)
                        document.getElementById('receiveAddress').textContent = 'Error: ' + e.message;
                        return;
                    }
                } else if (isFullNode && !connected) {
                    // Full node mode but not connected
                    document.getElementById('receiveAddress').textContent = 'Connect to node first (click Reconnect below)';
                    document.getElementById('qrContainer').style.display = 'none';
                    return;
                } else if (!isFullNode) {
                    // LIGHT WALLET MODE: Use browser wallet
                    if (!localWallet || !localWallet.isWalletUnlocked()) {
                        document.getElementById('receiveAddress').textContent = 'Unlock browser wallet (Settings → Wallet Setup)';
                        return;
                    }
                    let addresses = await localWallet.getAddresses();
                    if (addresses.length === 0) {
                        address = await localWallet.getNewAddress(0);
                    } else {
                        address = addresses[0].address;
                    }
                } else {
                    document.getElementById('receiveAddress').textContent = 'Connect to node to see address';
                    return;
                }

                document.getElementById('receiveAddress').textContent = address;

                // Generate QR code
                const qrCanvas = document.getElementById('qrcode');
                const qrContainer = document.getElementById('qrContainer');
                if (typeof QRCode !== 'undefined') {
                    try {
                        QRCode.toCanvas(qrCanvas, address, {
                            width: 200,
                            margin: 2,
                            color: {
                                dark: '#000000',
                                light: '#ffffff'
                            }
                        });
                        qrContainer.style.display = '';
                    } catch (qrErr) {
                        console.error('QR generation failed:', qrErr);
                        qrContainer.style.display = 'none';
                    }
                } else {
                    qrContainer.style.display = 'none';
                }

                // Show existing label if any
                updateAddressLabelDisplay(address);

                // Show mining address card if mining address differs from receive address
                const miningCard = document.getElementById('miningAddressCard');
                const miningAddrEl = document.getElementById('receiveMiningAddress');
                try {
                    const miningResult = await rpcCall('getminingaddress');
                    if (miningResult && miningResult.address && miningResult.address !== address) {
                        miningAddrEl.textContent = miningResult.address;
                        miningCard.style.display = '';
                    } else {
                        miningCard.style.display = 'none';
                    }
                } catch (e) {
                    miningCard.style.display = 'none';
                }
            } catch(e) {
                document.getElementById('receiveAddress').textContent = 'Error loading address';
                console.error('Address error:', e);
            }
        }

        // Update address label display
        function updateAddressLabelDisplay(address) {
            const labelEl = document.getElementById('currentAddressLabel');
            const inputEl = document.getElementById('addressLabelInput');
            const existingLabel = getAddressLabel(address);

            if (existingLabel) {
                labelEl.textContent = 'Label: ' + existingLabel;
                inputEl.value = existingLabel;
            } else {
                labelEl.textContent = '';
                inputEl.value = '';
            }
        }

        // Save label for current address
        function saveCurrentAddressLabel() {
            const address = document.getElementById('receiveAddress').textContent;
            const label = document.getElementById('addressLabelInput').value;

            if (!address || address === 'Loading...' || address === 'Error loading address') {
                alert('No address to label');
                return;
            }

            saveAddressLabel(address, label);
            updateAddressLabelDisplay(address);

            // Refresh transactions to show updated labels
            if (lastTransactions) {
                renderTransactions(lastTransactions);
            }
        }

        // Generate new address
        async function generateNewAddress() {
            const isFullNode = !connectionManager || connectionManager.getMode() === 'full';
            let newAddress;

            try {
                if (isFullNode && connected) {
                    // FULL NODE MODE: Generate address via node's wallet RPC
                    newAddress = await rpcCall('getnewaddress');
                } else if (!isFullNode) {
                    // LIGHT WALLET MODE: Generate in browser wallet
                    if (!localWallet || !localWallet.isWalletUnlocked()) {
                        showNotification('Please unlock your browser wallet first (Settings → Wallet Setup)', 'error');
                        return;
                    }
                    newAddress = await localWallet.getNewAddress(0);
                } else {
                    showNotification('Connect to node first', 'error');
                    return;
                }

                document.getElementById('receiveAddress').textContent = newAddress;

                // Generate QR code
                const qrCanvas2 = document.getElementById('qrcode');
                const qrContainer2 = document.getElementById('qrContainer');
                if (typeof QRCode !== 'undefined') {
                    try {
                        QRCode.toCanvas(qrCanvas2, newAddress, {
                            width: 200,
                            margin: 2,
                            color: { dark: '#000000', light: '#ffffff' }
                        });
                        qrContainer2.style.display = '';
                    } catch (qrErr) {
                        console.error('QR generation failed:', qrErr);
                        qrContainer2.style.display = 'none';
                    }
                } else {
                    qrContainer2.style.display = 'none';
                }

                updateAddressLabelDisplay(newAddress);
                showNotification('New address generated', 'success');
            } catch (e) {
                showNotification('Failed to generate address: ' + e.message, 'error');
            }
        }

        // Copy address
        async function copyAddress() {
            const address = document.getElementById('receiveAddress').textContent;
            try {
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    await navigator.clipboard.writeText(address);
                } else {
                    throw new Error('no clipboard API');
                }
            } catch (e) {
                const ta = document.createElement('textarea');
                ta.value = address;
                ta.style.position = 'fixed';
                ta.style.opacity = '0';
                document.body.appendChild(ta);
                ta.select();
                document.execCommand('copy');
                document.body.removeChild(ta);
            }
            const btn = document.getElementById('copyBtn');
            btn.textContent = 'Copied!';
            btn.classList.add('copied');
            setTimeout(() => {
                btn.textContent = 'Copy';
                btn.classList.remove('copied');
            }, 2000);
        }

        // Toggle address list visibility on dashboard
        function toggleAddressList() {
            const panel = document.getElementById('addressListPanel');
            const btn = document.getElementById('showAddressesBtn');
            const isHidden = panel.style.display === 'none';
            panel.style.display = isHidden ? '' : 'none';
            btn.textContent = isHidden ? 'Hide Addresses' : 'Show All Addresses';
            if (isHidden) {
                loadAddressBalances();
            }
        }

        // Load all wallet addresses with balances
        async function loadAddressBalances() {
            const content = document.getElementById('addressListContent');
            content.innerHTML = '<div style="color: #8A8A80; font-size: 13px; padding: 12px 0;">Loading...</div>';

            try {
                const isFullNode = !connectionManager || connectionManager.getMode() === 'full';
                let addressBalances = [];

                if (isFullNode && connected) {
                    // Get all addresses and UTXOs from node
                    const [addresses, utxos] = await Promise.all([
                        rpcCall('getaddresses'),
                        rpcCall('listunspent')
                    ]);

                    // Also get mining address
                    let miningAddr = null;
                    try {
                        const ma = await rpcCall('getminingaddress');
                        if (ma && ma.address) miningAddr = ma.address;
                    } catch (e) {}

                    // Aggregate UTXO balances by address
                    const balanceMap = {};
                    for (const addr of addresses) {
                        balanceMap[addr] = 0;
                    }
                    for (const utxo of utxos) {
                        if (!balanceMap.hasOwnProperty(utxo.address)) {
                            balanceMap[utxo.address] = 0;
                        }
                        balanceMap[utxo.address] += utxo.amount;
                    }

                    // Build sorted list (addresses with balance first)
                    for (const [addr, bal] of Object.entries(balanceMap)) {
                        const isMining = addr === miningAddr;
                        addressBalances.push({ address: addr, balance: bal, isMining: isMining });
                    }
                    addressBalances.sort((a, b) => b.balance - a.balance);

                } else if (!isFullNode) {
                    // Light wallet mode — query balances via HTTPS API
                    if (!localWallet || !localWallet.isWalletUnlocked()) {
                        content.innerHTML = '<div style="color: #8A8A80; font-size: 13px; padding: 12px 0;">Unlock your wallet to see address balances</div>';
                        return;
                    }
                    const addresses = await localWallet.getAddresses();
                    for (const a of addresses) {
                        let bal = 0;
                        try {
                            const balInfo = await connectionManager.getBalance(a.address);
                            bal = (balInfo.confirmed || 0) / 100000000;
                        } catch (e) {}
                        addressBalances.push({ address: a.address, balance: bal, isMining: false });
                    }
                } else {
                    content.innerHTML = '<div style="color: #8A8A80; font-size: 13px; padding: 12px 0;">Connecting...</div>';
                    return;
                }

                if (addressBalances.length === 0) {
                    content.innerHTML = '<div style="color: #8A8A80; font-size: 13px; padding: 12px 0;">No addresses found</div>';
                    return;
                }

                // Determine coin label
                const coinLabel = (typeof activeChain !== 'undefined' && activeChain === 'dilv') ? 'DilV' : 'DIL';

                // Split into addresses with balance and empty addresses
                const withBalance = addressBalances.filter(a => a.balance > 0 || a.isMining);
                const emptyAddrs = addressBalances.filter(a => a.balance <= 0 && !a.isMining);

                function renderAddressRow(item) {
                    const label = getAddressLabel(item.address);
                    const tags = [];
                    if (item.isMining) tags.push('<span style="background: rgba(200,181,96,0.2); color: #C8B560; font-size: 10px; padding: 2px 6px; border-radius: 3px; margin-left: 6px;">MINING</span>');
                    if (label) tags.push('<span style="color: #8A8A80; font-size: 11px; margin-left: 6px;">' + label + '</span>');

                    const balText = item.balance !== null
                        ? '<span style="color: ' + (item.balance > 0 ? '#22c55e' : '#8A8A80') + '; font-size: 13px; white-space: nowrap;">' + item.balance.toFixed(8) + ' ' + coinLabel + '</span>'
                        : '<span style="color: #8A8A80; font-size: 12px;">Balance requires node</span>';

                    return `
                        <div style="display: flex; align-items: center; justify-content: space-between; padding: 10px; background: rgba(138,138,128,0.05); border-radius: 4px; gap: 8px;">
                            <div style="min-width: 0; flex: 1;">
                                <div style="display: flex; align-items: center; flex-wrap: wrap;">
                                    <span style="font-family: monospace; font-size: 12px; color: #e0e0d0; word-break: break-all;">${item.address}</span>
                                    ${tags.join('')}
                                </div>
                            </div>
                            <div style="display: flex; align-items: center; gap: 6px; flex-shrink: 0;">
                                ${balText}
                                <button class="copy-btn" onclick="copyText('${item.address}')" style="padding: 3px 8px; font-size: 10px;">Copy</button>
                            </div>
                        </div>`;
                }

                let html = '';
                if (withBalance.length === 0) {
                    html += '<div style="color: #8A8A80; font-size: 13px; padding: 12px 0;">No addresses with balance found</div>';
                } else {
                    for (const item of withBalance) {
                        html += renderAddressRow(item);
                    }
                }

                if (emptyAddrs.length > 0) {
                    html += `
                        <button class="btn btn-secondary" onclick="toggleEmptyAddresses()" id="emptyAddrsBtn" style="width: 100%; margin-top: 8px; padding: 8px; font-size: 12px;">
                            Show ${emptyAddrs.length} Empty Addresses
                        </button>
                        <div id="emptyAddressList" style="display: none; flex-direction: column; gap: 4px; margin-top: 4px;">`;
                    // Pre-render but hidden
                    html += '</div>';
                    // Store empty addresses for lazy render
                    window._emptyAddresses = emptyAddrs;
                    window._renderAddressRow = renderAddressRow;
                }

                content.innerHTML = html;

            } catch (e) {
                console.error('[AddressList] Error:', e);
                content.innerHTML = '<div style="color: #ff6b6b; font-size: 13px; padding: 12px 0;">Error loading addresses: ' + e.message + '</div>';
            }
        }

        // Toggle empty addresses visibility
        function toggleEmptyAddresses() {
            const container = document.getElementById('emptyAddressList');
            const btn = document.getElementById('emptyAddrsBtn');
            if (container.style.display === 'none') {
                // Lazy render on first open
                if (container.innerHTML === '' && window._emptyAddresses) {
                    let html = '';
                    for (const item of window._emptyAddresses) {
                        html += window._renderAddressRow(item);
                    }
                    container.innerHTML = html;
                }
                container.style.display = 'flex';
                btn.textContent = 'Hide Empty Addresses';
            } else {
                container.style.display = 'none';
                btn.textContent = 'Show ' + (window._emptyAddresses ? window._emptyAddresses.length : '') + ' Empty Addresses';
            }
        }

        // Generic copy text helper
        function copyText(text) {
            navigator.clipboard.writeText(text).then(() => {
                showNotification('Address copied', 'success');
            }).catch(() => {
                const ta = document.createElement('textarea');
                ta.value = text;
                document.body.appendChild(ta);
                ta.select();
                document.execCommand('copy');
                document.body.removeChild(ta);
                showNotification('Address copied', 'success');
            });
        }

        // Mnemonic auto-hide timeout
        let mnemonicHideTimeout = null;
        let mnemonicCountdownInterval = null;
        const MNEMONIC_DISPLAY_SECONDS = 60;

        // Show mnemonic recovery phrase
        async function showMnemonic() {
            const alertDiv = document.getElementById('backupAlert');
            const password = document.getElementById('exportPassword').value;
            const isLightMode = connectionManager && connectionManager.getMode() === 'light';

            // Light mode: mnemonic not stored after creation
            if (isLightMode) {
                alertDiv.innerHTML = '<div class="alert" style="background: rgba(245,158,11,0.1); border: 1px solid rgba(245,158,11,0.3); color: var(--warning); line-height: 1.6;">' +
                    '<strong>Browser Wallet</strong><br>' +
                    'Your recovery phrase was shown when you created the wallet. It is not stored in the browser for security.<br><br>' +
                    'If you lost it, you cannot recover it from here. If you have a node wallet with the same keys, you can export the mnemonic from your node using the <strong>Node Wallet</strong> at <a href="http://127.0.0.1:8332/" style="color:var(--warning);text-decoration:underline;">http://127.0.0.1:8332/</a>.<br><br>' +
                    'To import a mnemonic into this browser wallet, use the <strong>Recover Wallet</strong> section below.</div>';
                return;
            }

            // Show confirmation dialog first
            const confirmed = confirm(
                "WARNING: You are about to display your recovery phrase.\n\n" +
                "Anyone who sees these 24 words can steal ALL your funds.\n\n" +
                "Make sure:\n" +
                "- No one is watching your screen\n" +
                "- No screen recording is active\n" +
                "- You are in a private location\n\n" +
                "The phrase will auto-hide after 60 seconds.\n\n" +
                "Do you want to continue?"
            );

            if (!confirmed) {
                return;
            }

            try {
                // First check if this is an HD wallet
                const hdInfo = await rpcCall('gethdwalletinfo');
                console.log('[Mnemonic] HD wallet info:', hdInfo);
                if (!hdInfo || hdInfo.hdwallet === false) {
                    throw new Error('This wallet was not created as an HD wallet. No recovery phrase is available. Your wallet uses randomly generated keys - make sure to keep a backup of your wallet.dat file instead.');
                }

                // Check wallet encryption status
                const walletInfo = await rpcCall('getwalletinfo');
                console.log('[Mnemonic] Wallet info:', walletInfo);
                const isEncrypted = walletInfo && walletInfo.encrypted;

                // If encrypted, always try to unlock with provided password
                // (the wallet may report locked:false but still need re-unlocking)
                if (isEncrypted) {
                    if (!password) {
                        throw new Error('Wallet is encrypted. Please enter your password to export the recovery phrase.');
                    }
                    // Try to unlock (or re-unlock to ensure fresh unlock state)
                    try {
                        await rpcCall('walletpassphrase', {passphrase: password, timeout: 60});
                        console.log('[Mnemonic] Wallet unlocked successfully');
                    } catch(e) {
                        console.error('[Mnemonic] Wallet unlock failed:', e.message);
                        // Check if it's a password error vs other error
                        if (e.message.includes('passphrase') || e.message.includes('incorrect')) {
                            throw new Error('Incorrect password. Please try again.');
                        }
                        // Otherwise continue - maybe wallet doesn't need unlocking
                        console.log('[Mnemonic] Continuing despite unlock error');
                    }
                }

                const result = await rpcCall('exportmnemonic');
                console.log('[Mnemonic] Export result:', result ? 'success' : 'null');

                if (result && result.mnemonic) {
                    const words = result.mnemonic.split(' ');
                    const wordsContainer = document.getElementById('mnemonicWords');
                    wordsContainer.innerHTML = '';

                    words.forEach((word, index) => {
                        const wordDiv = document.createElement('div');
                        wordDiv.style.cssText = 'background: var(--bg-darker); padding: 10px 12px; border-radius: 6px; border: 1px solid var(--border); font-family: "JetBrains Mono", monospace; font-size: 0.85rem;';
                        wordDiv.innerHTML = `<span style="color: var(--text-muted); margin-right: 8px;">${index + 1}.</span>${word}`;
                        wordsContainer.appendChild(wordDiv);
                    });

                    document.getElementById('mnemonicDisplay').style.display = 'block';
                    document.getElementById('mnemonicHidden').style.display = 'none';
                    alertDiv.innerHTML = '';

                    // Start auto-hide countdown
                    startMnemonicCountdown();
                } else {
                    throw new Error('No mnemonic returned. This wallet may not be an HD wallet.');
                }
            } catch(e) {
                console.error('[Mnemonic] Export error:', e);
                let errorMsg = e.message;

                // Provide clearer error messages for common issues
                if (errorMsg.includes('Failed to export mnemonic') || errorMsg.includes('wallet may be locked')) {
                    // If we already unlocked successfully, this likely means mnemonic wasn't stored
                    errorMsg = 'Unable to export recovery phrase. This wallet may have been created before HD wallet support, or the recovery phrase was not saved during wallet creation. Please backup your wallet.dat file instead.';
                }

                alertDiv.innerHTML = `<div class="alert alert-error">${errorMsg}</div>`;
            }
        }

        // Start countdown timer for auto-hide
        function startMnemonicCountdown() {
            // Clear any existing timers
            clearMnemonicTimers();

            let secondsLeft = MNEMONIC_DISPLAY_SECONDS;
            const hideBtn = document.querySelector('#mnemonicDisplay button');

            // Update button text with countdown every second
            mnemonicCountdownInterval = setInterval(() => {
                if (secondsLeft > 0 && document.getElementById('mnemonicDisplay').style.display !== 'none') {
                    hideBtn.textContent = `Hide Recovery Phrase (${secondsLeft}s)`;
                    secondsLeft--;
                } else {
                    clearMnemonicTimers();
                }
            }, 1000);

            // Auto-hide after timeout
            mnemonicHideTimeout = setTimeout(() => {
                hideMnemonic();
            }, MNEMONIC_DISPLAY_SECONDS * 1000);
        }

        // Clear mnemonic timers
        function clearMnemonicTimers() {
            if (mnemonicHideTimeout) {
                clearTimeout(mnemonicHideTimeout);
                mnemonicHideTimeout = null;
            }
            if (mnemonicCountdownInterval) {
                clearInterval(mnemonicCountdownInterval);
                mnemonicCountdownInterval = null;
            }
        }

        // Hide mnemonic
        function hideMnemonic() {
            // Clear timers
            clearMnemonicTimers();

            document.getElementById('mnemonicDisplay').style.display = 'none';
            document.getElementById('mnemonicHidden').style.display = 'block';
            document.getElementById('mnemonicWords').innerHTML = '';
            document.getElementById('exportPassword').value = '';

            // Reset button text
            const hideBtn = document.querySelector('#mnemonicDisplay button');
            if (hideBtn) {
                hideBtn.textContent = 'Hide Recovery Phrase';
            }

            // Lock wallet again
            rpcCall('walletlock', {}).catch(() => {});
        }

        // Recover wallet from mnemonic
        async function recoverWallet() {
            const alertDiv = document.getElementById('backupAlert');
            const mnemonicInput = document.getElementById('recoveryMnemonic').value.trim();
            const passphrase = document.getElementById('recoveryPassphrase').value;
            const isLightMode = connectionManager && connectionManager.getMode() === 'light';

            // Validate mnemonic
            const words = mnemonicInput.toLowerCase().split(/\s+/).filter(w => w.length > 0);
            if (words.length !== 24) {
                alertDiv.innerHTML = `<div class="alert alert-error">Invalid recovery phrase. Please enter exactly 24 words. You entered ${words.length} words.</div>`;
                return;
            }

            const mnemonic = words.join(' ');

            if (isLightMode) {
                // Light mode: import into browser wallet
                if (!passphrase || passphrase.length < 8) {
                    alertDiv.innerHTML = '<div class="alert alert-error">Enter a password (8+ characters) to encrypt your browser wallet.</div>';
                    return;
                }

                alertDiv.innerHTML = '<div class="alert" style="background: rgba(200, 162, 78, 0.1); border: 1px solid rgba(200, 162, 78, 0.3); color: var(--primary);">Importing wallet... This may take a moment.</div>';

                try {
                    await localWallet.importWallet(passphrase, words);
                    alertDiv.innerHTML = '<div class="alert alert-success">Wallet imported! Scanning for addresses...</div>';
                    document.getElementById('recoveryMnemonic').value = '';
                    document.getElementById('recoveryPassphrase').value = '';
                    updateLightWalletUI();

                    // HD address scan
                    if (connectionManager && connectionManager.isConnected()) {
                        const result = await localWallet.scanHDAddresses(connectionManager, (index, found) => {
                            alertDiv.innerHTML = `<div class="alert" style="background: rgba(200,162,78,0.1); border: 1px solid rgba(200,162,78,0.3); color: var(--primary);">Scanning: checked ${index} addresses, found ${found} with balance...</div>`;
                        });
                        alertDiv.innerHTML = `<div class="alert alert-success">Import complete! Found ${result.found + 1} addresses with balance.</div>`;
                    }
                    await refreshBalance();
                } catch(e) {
                    alertDiv.innerHTML = `<div class="alert alert-error">Import failed: ${e.message}</div>`;
                }
                return;
            }

            // Full node mode: use RPC
            alertDiv.innerHTML = '<div class="alert" style="background: rgba(200, 162, 78, 0.1); border: 1px solid rgba(200, 162, 78, 0.3); color: var(--primary);">Recovering wallet... This may take a moment.</div>';

            try {
                const params = {mnemonic: mnemonic};
                if (passphrase) {
                    params.passphrase = passphrase;
                }

                const result = await rpcCall('restorehdwallet', params);

                alertDiv.innerHTML = `
                    <div class="alert alert-success">
                        Wallet recovered successfully!<br>
                        <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.85rem;">
                            Address: ${result.address || 'Generated'}
                        </span>
                    </div>
                `;

                // Clear the input fields
                document.getElementById('recoveryMnemonic').value = '';
                document.getElementById('recoveryPassphrase').value = '';

                // Refresh wallet data
                await refreshBalance();
                await refreshReceiveAddress();
                await refreshTransactions();
            } catch(e) {
                alertDiv.innerHTML = `<div class="alert alert-error">Recovery failed: ${e.message}</div>`;
            }
        }

        // Handle send
        // Pending send data for confirmation flow
        let pendingSend = null;

        async function handleSend(event) {
            event.preventDefault();
            const toAddress = document.getElementById('sendAddress').value;
            const amount = parseFloat(document.getElementById('sendAmount').value);
            const alertDiv = document.getElementById('sendAlert');
            const sendBtn = document.getElementById('sendBtn');

            if (!toAddress || !amount || amount <= 0) {
                alertDiv.innerHTML = '<div class="alert alert-error">Please enter a valid address and amount</div>';
                return;
            }

            sendBtn.disabled = true;
            sendBtn.innerHTML = '<div class="spinner" style="width: 16px; height: 16px; margin: 0;"></div> Estimating fee...';

            const isFullNode = !connectionManager || connectionManager.getMode() === 'full';

            try {
                if (isFullNode && connected) {
                    // FULL NODE MODE: Estimate fee first, then show confirmation
                    const estimate = await rpcCall('estimatesendfee', {address: toAddress, amount: amount});
                    pendingSend = { address: toAddress, amount: amount, fee: estimate.fee, total: estimate.total };

                    alertDiv.innerHTML = `
                        <div style="background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 8px; padding: 16px;">
                            <div style="font-weight: 600; margin-bottom: 12px; font-size: 0.95rem;">Confirm Transaction</div>
                            <table style="width: 100%; font-size: 0.85rem; border-collapse: collapse;">
                                <tr>
                                    <td style="padding: 4px 0; color: var(--text-muted);">To</td>
                                    <td style="padding: 4px 0; text-align: right; font-family: 'JetBrains Mono', monospace; font-size: 0.75rem;">${toAddress.substring(0, 12)}...${toAddress.substring(toAddress.length - 6)}</td>
                                </tr>
                                <tr>
                                    <td style="padding: 4px 0; color: var(--text-muted);">Amount</td>
                                    <td style="padding: 4px 0; text-align: right; font-weight: 600;">${amount.toFixed(8)} ${chainUnits[activeChain]}</td>
                                </tr>
                                <tr>
                                    <td style="padding: 4px 0; color: var(--text-muted);">Network Fee</td>
                                    <td style="padding: 4px 0; text-align: right;">${estimate.fee.toFixed(8)} ${chainUnits[activeChain]}</td>
                                </tr>
                                <tr style="border-top: 1px solid var(--border);">
                                    <td style="padding: 8px 0 4px; font-weight: 600;">Total</td>
                                    <td style="padding: 8px 0 4px; text-align: right; font-weight: 600; color: var(--primary);">${estimate.total.toFixed(8)} ${chainUnits[activeChain]}</td>
                                </tr>
                            </table>
                            <div style="display: flex; gap: 8px; margin-top: 12px;">
                                <button class="btn btn-primary" onclick="confirmSend()" style="flex: 1;">Confirm & Send</button>
                                <button class="btn" onclick="cancelSend()" style="flex: 1; background: var(--bg-secondary); border: 1px solid var(--border);">Cancel</button>
                            </div>
                        </div>
                    `;
                    sendBtn.disabled = false;
                    sendBtn.style.display = 'none';
                    return;
                } else if (!isFullNode) {
                    // LIGHT WALLET MODE: Use browser wallet + transaction builder
                    if (!localWallet || !localWallet.isWalletUnlocked()) {
                        throw new Error('Please unlock your browser wallet first (Settings → Wallet Setup)');
                    }
                    if (!txBuilder) {
                        throw new Error('Transaction builder not initialized');
                    }

                    const addresses = await localWallet.getAddresses();
                    if (addresses.length === 0) {
                        throw new Error('No addresses in wallet. Generate an address first.');
                    }

                    let fromAddress = null;
                    let totalBalance = 0;
                    for (const addr of addresses) {
                        const balanceInfo = await connectionManager.getBalance(addr.address);
                        const balance = (balanceInfo.confirmed || 0) / 100000000;
                        totalBalance += balance;
                        if (balance >= amount && !fromAddress) {
                            fromAddress = addr.address;
                        }
                    }

                    if (!fromAddress) {
                        throw new Error(`Insufficient balance. You have ${totalBalance.toFixed(8)} ${chainUnits[activeChain]} but need ${amount} ${chainUnits[activeChain]}`);
                    }

                    const result = await txBuilder.send(fromAddress, toAddress, amount);
                    showSendSuccess(result.txid);
                } else {
                    throw new Error('Connect to node first');
                }
            } catch(e) {
                alertDiv.innerHTML = `<div class="alert alert-error">Error: ${e.message}</div>`;
            }

            resetSendButton();
        }

        async function confirmSend() {
            if (!pendingSend) return;
            const alertDiv = document.getElementById('sendAlert');
            alertDiv.innerHTML = '<div style="text-align: center; padding: 16px;"><div class="spinner" style="width: 20px; height: 20px; margin: 0 auto;"></div><div style="margin-top: 8px; font-size: 0.85rem; color: var(--text-muted);">Sending transaction...</div></div>';

            try {
                const txid = await rpcCall('sendtoaddress', {address: pendingSend.address, amount: pendingSend.amount});
                showSendSuccess(typeof txid === 'object' ? txid.txid : txid);
                pendingSend = null;
                resetSendButton();
            } catch(e) {
                const msg = (e.message || '').toLowerCase();
                if (msg.includes('locked') || msg.includes('unlock')) {
                    // Show inline unlock prompt instead of raw error
                    alertDiv.innerHTML = `
                        <div class="alert alert-error" style="margin-bottom: 12px;">Wallet is locked. Enter your password to unlock and send.</div>
                        <div style="display: flex; gap: 8px; align-items: center;">
                            <input type="password" class="form-input" id="sendUnlockPassword" placeholder="Wallet password"
                                   style="flex: 1;" onkeypress="if(event.key==='Enter')unlockAndSend()">
                            <button class="btn btn-primary" onclick="unlockAndSend()">Unlock & Send</button>
                            <button class="btn" onclick="cancelSend()" style="background: var(--bg-secondary); border: 1px solid var(--border);">Cancel</button>
                        </div>
                    `;
                    // Focus the password input
                    setTimeout(() => document.getElementById('sendUnlockPassword')?.focus(), 50);
                } else {
                    alertDiv.innerHTML = `<div class="alert alert-error">Error: ${e.message}</div>`;
                    pendingSend = null;
                    resetSendButton();
                }
            }
        }

        async function unlockAndSend() {
            const password = document.getElementById('sendUnlockPassword')?.value;
            if (!password) {
                showNotification('Please enter your wallet password', 'error');
                return;
            }
            const alertDiv = document.getElementById('sendAlert');
            alertDiv.innerHTML = '<div style="text-align: center; padding: 16px;"><div class="spinner" style="width: 20px; height: 20px; margin: 0 auto;"></div><div style="margin-top: 8px; font-size: 0.85rem; color: var(--text-muted);">Unlocking wallet and sending...</div></div>';

            try {
                await rpcCall('walletpassphrase', { passphrase: password, timeout: 300 });
                walletLocked = false;
                updateLockUI();
                const txid = await rpcCall('sendtoaddress', {address: pendingSend.address, amount: pendingSend.amount});
                showSendSuccess(typeof txid === 'object' ? txid.txid : txid);
            } catch(e) {
                alertDiv.innerHTML = `<div class="alert alert-error">Error: ${e.message}</div>`;
            }
            pendingSend = null;
            resetSendButton();
        }

        function cancelSend() {
            pendingSend = null;
            document.getElementById('sendAlert').innerHTML = '';
            resetSendButton();
        }

        function showSendSuccess(txid) {
            const alertDiv = document.getElementById('sendAlert');
            alertDiv.innerHTML = `
                <div class="alert alert-success">
                    Transaction sent successfully!<br>
                    <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.75rem;">
                        TXID: ${txid}
                    </span>
                </div>
            `;
            document.getElementById('sendAddress').value = '';
            document.getElementById('sendAmount').value = '';
            refreshBalance();
            refreshTransactions();
        }

        function resetSendButton() {
            const sendBtn = document.getElementById('sendBtn');
            sendBtn.disabled = false;
            sendBtn.style.display = '';
            sendBtn.innerHTML = `
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <line x1="22" y1="2" x2="11" y2="13"></line>
                    <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>
                </svg>
                Send Transaction
            `;
        }

        // =====================================================================
        // Wallet Security Functions
        // =====================================================================

        let walletEncrypted = false;
        let walletLocked = true;

        // Check wallet encryption and lock status
        async function checkSecurityStatus() {
            if (!connected) {
                document.getElementById('encryptionIcon').textContent = '❓';
                document.getElementById('encryptionLabel').textContent = 'Not connected';
                document.getElementById('encryptionDesc').textContent = 'Connect to node to check security status';
                return;
            }

            try {
                const info = await rpcCall('getwalletinfo');

                // Check if encrypted
                walletEncrypted = info.encrypted === true;

                if (walletEncrypted) {
                    document.getElementById('encryptionIcon').textContent = '✅';
                    document.getElementById('encryptionLabel').textContent = 'Wallet is encrypted';
                    document.getElementById('encryptionLabel').style.color = '#22c55e';
                    document.getElementById('encryptionDesc').textContent = 'Your wallet file is protected with a password';

                    // Show lock/unlock section, hide encrypt section
                    document.getElementById('encryptSection').style.display = 'none';
                    document.getElementById('lockSection').style.display = 'block';

                    // Check lock status
                    walletLocked = info.unlocked_until === 0 || info.unlocked_until === undefined;
                    updateLockUI();
                } else {
                    document.getElementById('encryptionIcon').textContent = '⚠️';
                    document.getElementById('encryptionLabel').textContent = 'Wallet is NOT encrypted';
                    document.getElementById('encryptionLabel').style.color = '#ef4444';
                    document.getElementById('encryptionDesc').textContent = 'Your funds are at risk! Encrypt now.';

                    // Show encrypt section, hide lock section
                    document.getElementById('encryptSection').style.display = 'block';
                    document.getElementById('lockSection').style.display = 'none';
                }
            } catch (e) {
                console.error('Failed to check security status:', e);
                document.getElementById('encryptionIcon').textContent = '❓';
                document.getElementById('encryptionLabel').textContent = 'Unable to check status';
                document.getElementById('encryptionDesc').textContent = e.message || 'RPC error';
            }
        }

        // Update lock/unlock UI
        function updateLockUI() {
            if (walletLocked) {
                document.getElementById('lockIcon').textContent = '🔒';
                document.getElementById('lockLabel').textContent = 'Wallet is locked';
                document.getElementById('lockLabel').style.color = '#22c55e';
                document.getElementById('unlockForm').style.display = 'block';
                document.getElementById('lockForm').style.display = 'none';
            } else {
                document.getElementById('lockIcon').textContent = '🔓';
                document.getElementById('lockLabel').textContent = 'Wallet is unlocked';
                document.getElementById('lockLabel').style.color = '#f59e0b';
                document.getElementById('unlockForm').style.display = 'none';
                document.getElementById('lockForm').style.display = 'block';
            }
        }

        // Encrypt wallet
        async function encryptWallet() {
            const password = document.getElementById('newWalletPassword').value;
            const confirm = document.getElementById('confirmWalletPassword').value;

            // Validate
            if (password.length < 12) {
                showNotification('Password must be at least 12 characters', 'error');
                return;
            }

            if (password !== confirm) {
                showNotification('Passwords do not match', 'error');
                return;
            }

            // Confirm action
            if (!window.confirm('⚠️ IMPORTANT: Write down your password somewhere safe!\n\nIf you forget this password, you will need your 24-word recovery phrase to access your funds.\n\nThe node will restart after encryption.\n\nContinue?')) {
                return;
            }

            try {
                showNotification('Encrypting wallet...', 'info');
                await rpcCall('encryptwallet', { passphrase: password });
                showNotification('Wallet encrypted successfully! Node is restarting...', 'success');

                // Clear password fields
                document.getElementById('newWalletPassword').value = '';
                document.getElementById('confirmWalletPassword').value = '';

                // Node will restart, so we'll lose connection
                setTimeout(() => {
                    showNotification('Reconnecting to node...', 'info');
                    connect();
                }, 3000);
            } catch (e) {
                showNotification('Encryption failed: ' + (e.message || 'Unknown error'), 'error');
            }
        }

        // Unlock wallet
        async function unlockWallet() {
            const password = document.getElementById('unlockPassword').value;
            const duration = parseInt(document.getElementById('unlockDuration').value) || 300;

            if (!password) {
                showNotification('Please enter your wallet password', 'error');
                return;
            }

            try {
                await rpcCall('walletpassphrase', { passphrase: password, timeout: duration });
                showNotification('Wallet unlocked for ' + duration + ' seconds', 'success');
                document.getElementById('unlockPassword').value = '';
                walletLocked = false;
                updateLockUI();
            } catch (e) {
                showNotification('Unlock failed: ' + (e.message || 'Wrong password?'), 'error');
            }
        }

        // Lock wallet
        async function lockWallet() {
            try {
                await rpcCall('walletlock');
                showNotification('Wallet locked', 'success');
                walletLocked = true;
                updateLockUI();
            } catch (e) {
                showNotification('Lock failed: ' + (e.message || 'Unknown error'), 'error');
            }
        }

        // ========================================================================
        // Bridge Functions
        // ========================================================================

        const BRIDGE_CONFIG = {
            chainId: 8453,
            chainName: 'Base',
            rpcUrl: 'https://mainnet.base.org',
            wdilContract: '0x30629128d1d3524F1A01B9c385FbE84fDCbD36C2',
            wdilvContract: '0xF162F6B432FeeD73458D4653ef8E74Ba014403E8',
            dilBridgeAddress: 'DNaTbwZgm6x23zf4DnJm4vjEG2qGc6cinx',
            dilvBridgeAddress: 'DTHGN3XiZ9LRxHVPUWMumX8B9q6B4BuPdp',
            burnAbi: [
                'function burn(uint256 amount, string calldata nativeAddress) external',
                'function balanceOf(address account) external view returns (uint256)',
                'function decimals() external view returns (uint8)',
                'function symbol() external view returns (string)'
            ]
        };

        const BRIDGE_LIMITS = {
            dil:  { maxPerDeposit: 500,  dailyCap: 1000,  coin: 'DIL',  wrapped: 'wDIL'  },
            dilv: { maxPerDeposit: 5000, dailyCap: 10000, coin: 'DilV', wrapped: 'wDILV' }
        };

        let bridgeProvider = null;
        let bridgeSigner = null;
        let bridgeConnectedAddress = null;
        let bridgeDepositChain = 'dil';
        let bridgeWithdrawChain = 'dil';

        function switchBridgeTab(tab) {
            document.querySelectorAll('.bridge-tab').forEach(t => {
                t.classList.remove('active');
                t.style.background = '';
                t.style.color = 'var(--text-secondary)';
            });
            const active = document.querySelector(`.bridge-tab[data-bridge-tab="${tab}"]`);
            if (active) {
                active.classList.add('active');
                active.style.background = 'var(--primary)';
                active.style.color = 'white';
            }
            document.getElementById('bridge-deposit-panel').style.display = tab === 'deposit' ? 'block' : 'none';
            document.getElementById('bridge-withdraw-panel').style.display = tab === 'withdraw' ? 'block' : 'none';
        }

        function bridgeSelectDepositChain(chain) {
            bridgeDepositChain = chain;
            const opts = document.querySelectorAll('.bridge-chain-opt');
            opts.forEach(o => { o.classList.remove('active'); o.style.background = ''; o.style.color = 'var(--text-muted)'; });
            opts[chain === 'dil' ? 0 : 1].classList.add('active');
            opts[chain === 'dil' ? 0 : 1].style.background = 'var(--primary)';
            opts[chain === 'dil' ? 0 : 1].style.color = 'white';

            const limits = BRIDGE_LIMITS[chain];
            document.getElementById('bridgeDepositCoinLabel').textContent = limits.coin;
            document.getElementById('bridgeWrappedLabel').textContent = limits.wrapped;
            document.getElementById('bridgeConfirmCount').textContent = chain === 'dil' ? '6' : '15';
            document.getElementById('bridgeConfirmTime').textContent = chain === 'dil' ? '~24 min' : '~12 min';
            document.getElementById('bridgeDepositLimitNote').textContent =
                `Max per deposit: ${limits.maxPerDeposit} ${limits.coin}. Daily limit: ${limits.dailyCap} ${limits.coin}.`;
            document.getElementById('bridgeDepositAmount').setAttribute('max', limits.maxPerDeposit);
            document.getElementById('bridgeTokenContract').textContent =
                chain === 'dil' ? BRIDGE_CONFIG.wdilContract : BRIDGE_CONFIG.wdilvContract;
            bridgeValidateDeposit();
        }

        function bridgeSelectWithdrawChain(chain) {
            bridgeWithdrawChain = chain;
            const opts = document.querySelectorAll('.bridge-wchain-opt');
            opts.forEach(o => { o.classList.remove('active'); o.style.background = ''; o.style.color = 'var(--text-muted)'; });
            opts[chain === 'dil' ? 0 : 1].classList.add('active');
            opts[chain === 'dil' ? 0 : 1].style.background = 'var(--primary)';
            opts[chain === 'dil' ? 0 : 1].style.color = 'white';
            bridgeUpdateWithdrawBtn();
        }

        function bridgeValidateDeposit() {
            const addr = document.getElementById('bridgeDepositBaseAddr').value.trim();
            const amount = document.getElementById('bridgeDepositAmount').value.trim();
            const btn = document.getElementById('bridgeDepositBtn');
            const limits = BRIDGE_LIMITS[bridgeDepositChain];

            if (!addr || !addr.startsWith('0x') || addr.length !== 42) {
                btn.textContent = 'Enter your MetaMask address';
                btn.disabled = true;
                return;
            }
            if (!amount || parseFloat(amount) <= 0) {
                btn.textContent = 'Enter amount to bridge';
                btn.disabled = true;
                return;
            }
            if (parseFloat(amount) > limits.maxPerDeposit) {
                btn.textContent = `Max ${limits.maxPerDeposit} ${limits.coin} per deposit`;
                btn.disabled = true;
                return;
            }
            btn.textContent = `Bridge ${amount} ${limits.coin} to ${limits.wrapped}`;
            btn.disabled = false;
        }

        function bridgeUpdateWithdrawBtn() {
            const btn = document.getElementById('bridgeWithdrawBtn');
            if (!bridgeSigner) {
                btn.textContent = 'Connect MetaMask First';
                btn.disabled = true;
            } else {
                const symbol = bridgeWithdrawChain === 'dil' ? 'wDIL' : 'wDILV';
                btn.textContent = `Burn ${symbol} & Withdraw`;
                btn.disabled = false;
            }
        }

        async function bridgeConnectWallet() {
            if (typeof window.ethereum === 'undefined') {
                const isMobile = /Android|iPhone|iPad/i.test(navigator.userAgent);
                if (isMobile) {
                    document.getElementById('bridgeMetaMaskStatus').innerHTML = `
                        <div style="background: rgba(245,158,11,0.1); border: 1px solid rgba(245,158,11,0.3); border-radius: 10px; padding: 16px; font-size: 0.85rem; line-height: 1.6;">
                            <strong style="color: var(--warning);">MetaMask on Mobile</strong>
                            <p style="color: var(--text-secondary); margin: 8px 0;">To connect MetaMask, open this wallet inside the <strong>MetaMask app's built-in browser</strong>:</p>
                            <ol style="color: var(--text-secondary); margin: 8px 0 12px 20px;">
                                <li>Open the <strong>MetaMask</strong> app</li>
                                <li>Tap <strong>Explore</strong> (magnifying glass icon) at the bottom</li>
                                <li>Paste this URL in the address bar:</li>
                            </ol>
                            <div onclick="navigator.clipboard.writeText('https://dilithion.org/wallet.html?mode=light').then(()=>{this.querySelector('span').textContent='Copied!';})" style="background: var(--bg-darker); border: 1px solid var(--border); border-radius: 8px; padding: 10px 14px; font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; color: var(--accent); cursor: pointer; word-break: break-all; display: flex; justify-content: space-between; align-items: center; gap: 8px;">
                                dilithion.org/wallet.html?mode=light
                                <span style="font-family: Inter, sans-serif; font-size: 0.7rem; color: var(--text-muted); white-space: nowrap;">Tap to copy</span>
                            </div>
                            <p style="color: var(--text-muted); margin: 10px 0 0; font-size: 0.8rem;">For deposits, you don't need MetaMask — just paste your 0x address above.</p>
                        </div>`;
                } else {
                    showNotification('MetaMask not installed. Install it to use withdraw, or just paste your 0x address for deposits.', 'error');
                }
                return;
            }
            try {
                bridgeProvider = new ethers.providers.Web3Provider(window.ethereum);
                await bridgeProvider.send('eth_requestAccounts', []);
                bridgeSigner = bridgeProvider.getSigner();
                bridgeConnectedAddress = await bridgeSigner.getAddress();

                const short = bridgeConnectedAddress.slice(0, 6) + '...' + bridgeConnectedAddress.slice(-4);
                document.getElementById('bridgeConnectBtn').textContent = short;
                document.getElementById('bridgeConnectBtn').style.background = 'var(--success)';
                document.getElementById('bridgeMetaMaskStatus').textContent = 'Connected: ' + short;

                // Auto-fill deposit address
                document.getElementById('bridgeDepositBaseAddr').value = bridgeConnectedAddress;
                bridgeValidateDeposit();

                // Switch to Base if needed
                const network = await bridgeProvider.getNetwork();
                if (network.chainId !== BRIDGE_CONFIG.chainId) {
                    try {
                        await window.ethereum.request({
                            method: 'wallet_switchEthereumChain',
                            params: [{ chainId: '0x' + BRIDGE_CONFIG.chainId.toString(16) }]
                        });
                    } catch (e) {
                        console.warn('Could not switch to Base:', e);
                    }
                }

                bridgeUpdateWithdrawBtn();
                showNotification('MetaMask connected on Base', 'success');
            } catch (e) {
                showNotification('MetaMask connection failed: ' + e.message, 'error');
            }
        }

        // Bridge deposit helpers (ported from bridge.html)
        // Note: BASE58_ALPHABET is already defined in dilithium-crypto.js
        const BRIDGE_BASE58 = typeof BASE58_ALPHABET !== 'undefined' ? BASE58_ALPHABET : '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

        function bridgeBase58Decode(str) {
            let n = BigInt(0);
            for (const c of str) {
                const idx = BRIDGE_BASE58.indexOf(c);
                if (idx < 0) throw new Error('Invalid Base58 character: ' + c);
                n = n * 58n + BigInt(idx);
            }
            const hex = n.toString(16).padStart(50, '0');
            const bytes = new Uint8Array(hex.match(/.{2}/g).map(b => parseInt(b, 16)));
            let leadingZeros = 0;
            for (const c of str) { if (c === '1') leadingZeros++; else break; }
            const result = new Uint8Array(leadingZeros + bytes.length);
            result.set(bytes, leadingZeros);
            return result;
        }

        function bridgeGetPubKeyHash(address) {
            return bridgeBase58Decode(address).slice(1, 21);
        }

        function bridgeBuildP2PKHScript(pubkeyHash) {
            const script = new Uint8Array(25);
            script[0] = 0x76; script[1] = 0xa9; script[2] = 20;
            script.set(pubkeyHash, 3);
            script[23] = 0x88; script[24] = 0xac;
            return script;
        }

        function bridgeBuildOpReturnScript(data) {
            const script = new Uint8Array(2 + data.length);
            script[0] = 0x6a; script[1] = data.length;
            script.set(data, 2);
            return script;
        }

        function bridgeCompactSize(n) {
            if (n < 253) return new Uint8Array([n]);
            if (n <= 0xFFFF) { const b = new Uint8Array(3); b[0] = 0xfd; b[1] = n & 0xff; b[2] = (n >> 8) & 0xff; return b; }
            const b = new Uint8Array(5); b[0] = 0xfe; b[1] = n & 0xff; b[2] = (n >> 8) & 0xff; b[3] = (n >> 16) & 0xff; b[4] = (n >> 24) & 0xff; return b;
        }

        function bridgeUint32LE(n) {
            const b = new Uint8Array(4); b[0] = n & 0xff; b[1] = (n >> 8) & 0xff; b[2] = (n >> 16) & 0xff; b[3] = (n >> 24) & 0xff; return b;
        }

        function bridgeUint64LE(n) {
            const b = new Uint8Array(8);
            const lo = n & 0xFFFFFFFF; const hi = Math.floor(n / 0x100000000) & 0xFFFFFFFF;
            b[0] = lo & 0xff; b[1] = (lo >> 8) & 0xff; b[2] = (lo >> 16) & 0xff; b[3] = (lo >> 24) & 0xff;
            b[4] = hi & 0xff; b[5] = (hi >> 8) & 0xff; b[6] = (hi >> 16) & 0xff; b[7] = (hi >> 24) & 0xff;
            return b;
        }

        function bridgeHexToBytes(hex) { return new Uint8Array(hex.match(/.{2}/g).map(b => parseInt(b, 16))); }
        function bridgeBytesToHex(bytes) { return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(''); }
        function bridgeReverseBytes(bytes) { return new Uint8Array(Array.from(bytes).reverse()); }
        function bridgeConcatBytes(...arrays) {
            let total = arrays.reduce((s, a) => s + a.length, 0);
            let result = new Uint8Array(total);
            let offset = 0;
            for (const arr of arrays) { result.set(arr, offset); offset += arr.length; }
            return result;
        }

        function bridgeBuildRawTx(inputs, bridgeAddr, depositSats, changeAddr, changeSats, opReturnData) {
            const OP_RETURN_VALUE = 50000;
            let parts = [];
            parts.push(bridgeUint32LE(1)); // version
            parts.push(bridgeCompactSize(inputs.length));
            for (const inp of inputs) {
                parts.push(bridgeReverseBytes(bridgeHexToBytes(inp.txid)));
                parts.push(bridgeUint32LE(inp.vout));
                parts.push(bridgeCompactSize(0)); // empty scriptSig
                parts.push(bridgeUint32LE(0xFFFFFFFF));
            }
            parts.push(bridgeCompactSize(3)); // 3 outputs
            // Output 1: bridge payment
            parts.push(bridgeUint64LE(depositSats));
            const bridgeScript = bridgeBuildP2PKHScript(bridgeGetPubKeyHash(bridgeAddr));
            parts.push(bridgeCompactSize(bridgeScript.length)); parts.push(bridgeScript);
            // Output 2: OP_RETURN
            const opReturnScript = bridgeBuildOpReturnScript(opReturnData);
            parts.push(bridgeUint64LE(OP_RETURN_VALUE));
            parts.push(bridgeCompactSize(opReturnScript.length)); parts.push(opReturnScript);
            // Output 3: change
            parts.push(bridgeUint64LE(changeSats));
            const changeScript = bridgeBuildP2PKHScript(bridgeGetPubKeyHash(changeAddr));
            parts.push(bridgeCompactSize(changeScript.length)); parts.push(changeScript);
            parts.push(bridgeUint32LE(0)); // locktime
            return bridgeConcatBytes(...parts);
        }

        async function bridgeExecuteDeposit() {
            const baseAddr = document.getElementById('bridgeDepositBaseAddr').value.trim();
            const amountStr = document.getElementById('bridgeDepositAmount').value.trim();
            const chain = bridgeDepositChain;
            const statusDiv = document.getElementById('bridgeDepositStatus');
            const btn = document.getElementById('bridgeDepositBtn');
            const isLightMode = connectionManager && connectionManager.getMode() === 'light';

            statusDiv.style.display = 'block';
            statusDiv.innerHTML = '';
            btn.disabled = true;

            const limits = BRIDGE_LIMITS[chain];
            const bridgeAddr = chain === 'dil' ? BRIDGE_CONFIG.dilBridgeAddress : BRIDGE_CONFIG.dilvBridgeAddress;
            const depositSats = Math.round(parseFloat(amountStr) * 1e8);
            const OP_RETURN_VALUE = 50000;
            const FEE_RATE = 6;
            const MAX_INPUTS = 50;

            function log(msg, type) {
                const color = type === 'error' ? 'var(--error)' : type === 'success' ? 'var(--success)' : 'var(--text-muted)';
                statusDiv.innerHTML += `<p style="color: ${color}; font-size: 0.8rem; margin: 3px 0;">${msg}</p>`;
                statusDiv.scrollTop = statusDiv.scrollHeight;
            }

            // Build OP_RETURN data (DBRG tag + Base address) — same for both modes
            const tag = new Uint8Array([0x44, 0x42, 0x52, 0x47]); // "DBRG"
            const baseAddrBytes = bridgeHexToBytes(baseAddr.slice(2));
            const opReturnData = bridgeConcatBytes(tag, baseAddrBytes);

            if (isLightMode) {
                // ============================================================
                // LIGHT MODE: Sign locally with browser wallet, broadcast via API
                // ============================================================
                try {
                    if (!localWallet || !localWallet.isWalletUnlocked()) {
                        log('Wallet is locked. Unlock it first in Settings.', 'error');
                        btn.disabled = false;
                        return;
                    }

                    // Step 1: Get addresses and UTXOs from API
                    log('Fetching UTXOs from network...');
                    const addresses = await localWallet.getAddresses();
                    let allUtxos = [];
                    for (const addr of addresses) {
                        try {
                            const utxoResponse = await connectionManager.getUTXOs(addr.address);
                            const utxos = utxoResponse.utxos || utxoResponse;
                            if (Array.isArray(utxos)) {
                                for (const u of utxos) {
                                    u.address = addr.address;
                                    u.addressPath = addr.path;
                                    u.amount_sats = u.value || u.amount || 0;
                                    allUtxos.push(u);
                                }
                            }
                        } catch (e) { /* skip failed addresses */ }
                    }

                    allUtxos = allUtxos.filter(u => u.address !== bridgeAddr);
                    allUtxos.sort((a, b) => b.amount_sats - a.amount_sats);
                    log('Found ' + allUtxos.length + ' UTXOs across ' + addresses.length + ' addresses.');

                    if (allUtxos.length === 0) {
                        log('No UTXOs available.', 'error');
                        btn.disabled = false;
                        return;
                    }

                    // Step 2: Select UTXOs
                    const estFeeSats = MAX_INPUTS * 5400 * FEE_RATE;
                    const needed = depositSats + estFeeSats + OP_RETURN_VALUE + 1000;
                    let selected = [];
                    let totalSats = 0;
                    for (const u of allUtxos) {
                        if (selected.length >= MAX_INPUTS) break;
                        selected.push(u);
                        totalSats += u.amount_sats;
                        if (totalSats >= needed) break;
                    }

                    const estSignedSize = selected.length * 5400 + 200;
                    const feeSats = estSignedSize * FEE_RATE;
                    const actualNeeded = depositSats + feeSats + OP_RETURN_VALUE;

                    if (totalSats < actualNeeded) {
                        log(`Insufficient funds. Have ${(totalSats / 1e8).toFixed(4)} ${limits.coin}, need ${(actualNeeded / 1e8).toFixed(4)}`, 'error');
                        btn.disabled = false;
                        return;
                    }

                    const changeSats = totalSats - depositSats - OP_RETURN_VALUE - feeSats;
                    const changeAddr = selected[0].address;
                    log(`Selected ${selected.length} UTXOs. Fee: ${(feeSats / 1e8).toFixed(4)} ${limits.coin}`);

                    // Step 3: Build transaction with OP_RETURN
                    log('Building transaction...');
                    const tx = txBuilder.buildTransaction(
                        selected.map(u => ({ txid: u.txid, vout: u.vout })),
                        bridgeAddr, depositSats, changeAddr, changeSats
                    );

                    // Add OP_RETURN output (between bridge payment and change)
                    const opReturnScript = new Uint8Array(2 + opReturnData.length);
                    opReturnScript[0] = 0x6a; // OP_RETURN
                    opReturnScript[1] = opReturnData.length;
                    opReturnScript.set(opReturnData, 2);
                    tx.outputs.splice(1, 0, { value: OP_RETURN_VALUE, scriptPubKey: Array.from(opReturnScript) });

                    // Step 4: Confirm
                    const confirmed = confirm(
                        `Bridge ${amountStr} ${limits.coin}?\n\n` +
                        `Fee: ${(feeSats / 1e8).toFixed(4)} ${limits.coin}\n` +
                        `To: ${baseAddr}\n` +
                        `Inputs: ${selected.length}`
                    );
                    if (!confirmed) { log('Cancelled.', 'error'); btn.disabled = false; return; }

                    // Step 5: Sign locally with browser wallet keys
                    log('Signing locally (' + selected.length + ' inputs)...');
                    const signingAddr = selected[0].address;
                    const addrRecord = (await localWallet.getAddresses()).find(a => a.address === signingAddr);
                    if (!addrRecord) throw new Error('Signing address not found in wallet');

                    const privateKey = await localWallet.getPrivateKey(signingAddr);
                    const keyData = await DilithiumCrypto.deriveChildKey(localWallet.decryptedSeed, addrRecord.path);
                    const signedTx = await txBuilder.signTransaction(tx, privateKey, keyData.publicKey);
                    const rawHex = txBuilder.serializeTransaction(signedTx);
                    log('Signed. Size: ' + (rawHex.length / 2 / 1024).toFixed(1) + ' KB');

                    // Step 6: Broadcast via API
                    log('Broadcasting...');
                    const result = await connectionManager.broadcast(rawHex);
                    log('Sent! TxID: ' + result.txid, 'success');
                    log(`${limits.wrapped} will arrive in your MetaMask after confirmations.`, 'success');

                } catch (e) {
                    log('Error: ' + e.message, 'error');
                }
            } else {
                // ============================================================
                // FULL NODE MODE: Use node RPC for UTXOs, signing, broadcasting
                // ============================================================
                try {
                    log('Connecting to node...');
                    let utxos;
                    try {
                        utxos = await rpcCall('listunspent');
                    } catch (e) {
                        log('Cannot connect to node. Is it running?', 'error');
                        btn.disabled = false;
                        return;
                    }
                    log('Connected. Found ' + utxos.length + ' UTXOs.');

                    for (const u of utxos) {
                        const amt = u.amount;
                        u.amount_sats = (typeof amt === 'number' && amt < 10000) ? Math.round(amt * 1e8) : parseInt(amt);
                    }
                    utxos = utxos.filter(u => u.address !== bridgeAddr);
                    utxos.sort((a, b) => b.amount_sats - a.amount_sats);

                    const estFeeSats = MAX_INPUTS * 5400 * FEE_RATE;
                    const needed = depositSats + estFeeSats + OP_RETURN_VALUE + 1000;
                    let selected = [];
                    let totalSats = 0;
                    for (const u of utxos) {
                        if (selected.length >= MAX_INPUTS) break;
                        selected.push(u);
                        totalSats += u.amount_sats;
                        if (totalSats >= needed) break;
                    }

                    const estSignedSize = selected.length * 5400 + 200;
                    const feeSats = estSignedSize * FEE_RATE;
                    const actualNeeded = depositSats + feeSats + OP_RETURN_VALUE;

                    if (totalSats < actualNeeded) {
                        log(`Insufficient funds. Have ${(totalSats / 1e8).toFixed(4)} ${limits.coin}, need ${(actualNeeded / 1e8).toFixed(4)}`, 'error');
                        btn.disabled = false;
                        return;
                    }

                    const changeSats = totalSats - depositSats - OP_RETURN_VALUE - feeSats;
                    const changeAddr = selected[0].address;
                    log(`Selected ${selected.length} UTXOs. Fee: ${(feeSats / 1e8).toFixed(4)} ${limits.coin}`);

                    log('Building transaction...');
                    const inputs = selected.map(u => ({ txid: u.txid, vout: u.vout }));
                    const rawTx = bridgeBuildRawTx(inputs, bridgeAddr, depositSats, changeAddr, changeSats, opReturnData);
                    const rawHex = bridgeBytesToHex(rawTx);

                    const confirmed = confirm(
                        `Bridge ${amountStr} ${limits.coin}?\n\n` +
                        `Fee: ${(feeSats / 1e8).toFixed(4)} ${limits.coin}\n` +
                        `To: ${baseAddr}\n` +
                        `Inputs: ${selected.length}`
                    );
                    if (!confirmed) { log('Cancelled.', 'error'); btn.disabled = false; return; }

                    log('Signing (' + selected.length + ' inputs)...');
                    const signResult = await rpcCall('signrawtransaction', { hex: rawHex }, 120000);
                    if (!signResult.complete) {
                        log('Signing failed: ' + JSON.stringify(signResult), 'error');
                        btn.disabled = false;
                        return;
                    }
                    log('Signed. Size: ' + (signResult.hex.length / 2 / 1024).toFixed(1) + ' KB');

                    log('Broadcasting...');
                    const txid = await rpcCall('sendrawtransaction', { hex: signResult.hex }, 120000);
                    log('Sent! TxID: ' + txid, 'success');
                    log(`${limits.wrapped} will arrive in your MetaMask after confirmations.`, 'success');

                } catch (e) {
                    log('Error: ' + e.message, 'error');
                }
            }

            btn.disabled = false;
            bridgeValidateDeposit();
        }

        async function bridgeExecuteBurn() {
            if (!bridgeSigner) { showNotification('Connect MetaMask first', 'error'); return; }

            const amount = document.getElementById('bridgeWithdrawAmount').value;
            const nativeAddr = document.getElementById('bridgeWithdrawNativeAddr').value.trim();

            if (!amount || parseFloat(amount) <= 0) { showNotification('Enter a valid amount', 'error'); return; }
            if (!nativeAddr || !nativeAddr.startsWith('D')) { showNotification('Enter a valid Dilithion address (starts with D)', 'error'); return; }

            const contractAddr = bridgeWithdrawChain === 'dil' ? BRIDGE_CONFIG.wdilContract : BRIDGE_CONFIG.wdilvContract;
            const resultDiv = document.getElementById('bridgeWithdrawResult');
            resultDiv.style.display = 'block';
            resultDiv.innerHTML = '<p style="color: var(--text-muted); font-size: 0.85rem;">Processing burn...</p>';

            try {
                const contract = new ethers.Contract(contractAddr, BRIDGE_CONFIG.burnAbi, bridgeSigner);
                const decimals = await contract.decimals();
                const amountWei = ethers.utils.parseUnits(amount, decimals);

                const balance = await contract.balanceOf(bridgeConnectedAddress);
                if (balance.lt(amountWei)) {
                    resultDiv.innerHTML = `<p style="color: var(--error); font-size: 0.85rem;">Insufficient balance. You have ${ethers.utils.formatUnits(balance, decimals)}</p>`;
                    return;
                }

                const tx = await contract.burn(amountWei, nativeAddr);
                resultDiv.innerHTML = `<p style="color: var(--text-muted); font-size: 0.85rem;">TX submitted: ${tx.hash.slice(0, 16)}... Waiting for confirmation...</p>`;

                const receipt = await tx.wait();
                const symbol = bridgeWithdrawChain === 'dil' ? 'wDIL' : 'wDILV';
                const coin = bridgeWithdrawChain === 'dil' ? 'DIL' : 'DilV';

                resultDiv.innerHTML = `
                    <div style="background: rgba(34,197,94,0.08); border: 1px solid rgba(34,197,94,0.3); border-radius: 8px; padding: 12px; font-size: 0.85rem;">
                        <p style="color: var(--success); font-weight: 600; margin-bottom: 8px;">Burn confirmed!</p>
                        <p style="color: var(--text-secondary);">Amount: ${amount} ${symbol}</p>
                        <p style="color: var(--text-secondary);">To: ${nativeAddr}</p>
                        <p style="color: var(--text-secondary);">Base TX: ${receipt.transactionHash.slice(0, 20)}...</p>
                        <p style="color: var(--text-muted); margin-top: 8px; font-size: 0.8rem;">
                            The bridge will send ${coin} to your address after ~12 Base block confirmations (~30s).
                        </p>
                    </div>
                `;
            } catch (e) {
                resultDiv.innerHTML = `<p style="color: var(--error); font-size: 0.85rem;">Burn failed: ${e.reason || e.message}</p>`;
            }
        }

        function bridgeInitTab() {
            const isLightMode = connectionManager && connectionManager.getMode() === 'light';

            // Both tabs work in both modes — light mode signs locally via WASM
            switchBridgeTab('deposit');

            bridgeSelectDepositChain('dil');
            bridgeSelectWithdrawChain('dil');
            // Show warning if on HTTPS (deposits need local node RPC)
            const warn = document.getElementById('bridgeHttpsWarning');
            if (warn) warn.style.display = window.location.protocol === 'https:' ? 'block' : 'none';
            // Auto-connect if MetaMask is already connected
            if (window.ethereum && window.ethereum.selectedAddress) {
                bridgeConnectWallet();
            }
        }

        // Navigation
        // Mobile navigation
        function mobileNavigate(pageName) {
            navigateTo(pageName);
            // Update mobile nav active state
            document.querySelectorAll('.mobile-nav-item').forEach(item => {
                item.classList.remove('active');
                if (item.dataset.mobilePage === pageName) {
                    item.classList.add('active');
                }
            });
            // Close more menu if open
            document.getElementById('mobileMoreOverlay').classList.remove('active');
        }

        function toggleMobileMore() {
            document.getElementById('mobileMoreOverlay').classList.toggle('active');
        }

        function navigateTo(pageName) {
            document.querySelectorAll('.nav-item').forEach(item => {
                item.classList.remove('active');
                if (item.dataset.page === pageName) {
                    item.classList.add('active');
                }
            });
            // Also update mobile nav
            document.querySelectorAll('.mobile-nav-item').forEach(item => {
                item.classList.remove('active');
                if (item.dataset.mobilePage === pageName) {
                    item.classList.add('active');
                }
            });

            document.querySelectorAll('.page').forEach(page => {
                page.classList.remove('active');
            });
            document.getElementById('page-' + pageName).classList.add('active');

            // Load page-specific data
            if (pageName === 'receive') {
                refreshReceiveAddress();
            }
            if (pageName === 'settings') {
                checkSecurityStatus();
                checkNodeWalletEncryption();
            }
            if (pageName === 'dashboard') {
                updateDashboardEncryptionBanner();
            }
            if (pageName === 'mining-stats') {
                refreshMiningStats();
            }
            if (pageName === 'bridge') {
                bridgeInitTab();
            }
            if (pageName === 'backup') {
                const isLight = connectionManager && connectionManager.getMode() === 'light';
                const label = document.getElementById('recoveryPassphraseLabel');
                const hint = document.getElementById('recoveryPassphraseHint');
                if (isLight && label && hint) {
                    label.textContent = 'Password (required)';
                    hint.textContent = 'Choose a password (8+ characters) to encrypt your wallet in the browser';
                    document.getElementById('recoveryPassphrase').placeholder = 'Choose a password to protect your wallet';
                } else if (label && hint) {
                    label.textContent = 'Passphrase (optional)';
                    hint.textContent = 'Only enter if you used a passphrase when creating the wallet';
                    document.getElementById('recoveryPassphrase').placeholder = 'Leave empty if you didn\'t set a passphrase';
                }
            }
        }

        // ========================================================================
        // Light Wallet Functions
        // ========================================================================

        let connectionManager = null;
        let localWallet = null;
        let txBuilder = null;
        let currentMnemonic = null;  // Temporary storage during wallet creation

        // Initialize light wallet modules
        async function initLightWallet() {
            try {
                // Initialize crypto module
                if (window.DilithiumCrypto) {
                    await window.DilithiumCrypto.init();
                    console.log('[LightWallet] Crypto module initialized');
                }

                // Initialize connection manager (don't auto-connect yet — welcome screen check happens later)
                if (window.ConnectionManager) {
                    connectionManager = new window.ConnectionManager();
                    connectionManager.init();

                    // Set UI to match saved mode, but don't connect
                    const savedMode = localStorage.getItem('dilithionWalletMode');
                    if (savedMode === 'light') {
                        document.getElementById('connectionMode').value = 'light';
                        const fullModeDesc = document.getElementById('fullModeDesc');
                        const lightModeDesc = document.getElementById('lightModeDesc');
                        const fullNodeSettings = document.getElementById('fullNodeSettingsCard');
                        if (fullModeDesc) fullModeDesc.style.display = 'none';
                        if (lightModeDesc) lightModeDesc.style.display = 'block';
                        if (fullNodeSettings) fullNodeSettings.style.display = 'none';
                        connectionManager.setMode('light');
                    }
                }

                // Initialize local wallet (always used in unified wallet architecture)
                if (window.LocalWallet) {
                    localWallet = new window.LocalWallet(window.DilithiumCrypto);
                    await localWallet.init();

                    // Listen for lock events
                    localWallet.on('lock', () => {
                        updateLightWalletUI();
                    });

                    // Update wallet UI to show current state
                    await updateLightWalletUI();
                }

                // Initialize transaction builder
                if (window.TransactionBuilder) {
                    txBuilder = new window.TransactionBuilder(connectionManager, window.DilithiumCrypto, localWallet);
                    // Set chain ID for sighash (DIL=1, DilV=2)
                    txBuilder.chainId = activeChain === 'dilv' ? 2 : 1;
                }

                console.log('[LightWallet] All modules initialized');
            } catch (e) {
                console.error('[LightWallet] Initialization error:', e);
            }
        }

        // Handle mode change (unified wallet - mode only affects connection, not keys)
        async function handleModeChange() {
            const mode = document.getElementById('connectionMode').value;
            const fullModeDesc = document.getElementById('fullModeDesc');
            const lightModeDesc = document.getElementById('lightModeDesc');
            const fullNodeSettings = document.getElementById('fullNodeSettingsCard');

            // Toggle mode-specific descriptions
            if (mode === 'light') {
                fullModeDesc.style.display = 'none';
                lightModeDesc.style.display = 'block';
                // Hide RPC settings in light mode (not needed)
                if (fullNodeSettings) fullNodeSettings.style.display = 'none';
            } else {
                fullModeDesc.style.display = 'block';
                lightModeDesc.style.display = 'none';
                // Show RPC settings in full mode (for advanced users)
                if (fullNodeSettings) fullNodeSettings.style.display = 'block';
            }

            // Save mode preference
            localStorage.setItem('dilithionWalletMode', mode);

            // Update connection manager and reconnect
            if (connectionManager) {
                setConnectionStatus(false, 'Connecting...');
                await connectionManager.setMode(mode);

                // Actually connect with new mode
                try {
                    if (mode === 'light') {
                        // Light mode: connect to seed node
                        await connectionManager.connect();
                        setConnectionStatus(true, 'Light Wallet');
                    } else {
                        // Full mode: will use RPC connect
                        connect();  // This handles full node connection
                        return;     // connect() calls refreshAll() on success
                    }
                } catch (e) {
                    setConnectionStatus(false, 'Connection failed');
                    showNotification('Failed to connect: ' + e.message, 'warning');
                }
            }

            // Update node wallet security card visibility
            await checkNodeWalletEncryption();
            await updateDashboardEncryptionBanner();

            // Update wallet UI (same wallet, just different connection)
            await updateLightWalletUI();

            // Refresh data with new connection
            await refreshAll();
        }

        // Update light wallet UI based on wallet state
        async function updateLightWalletUI() {
            if (!localWallet) return;

            const hasWallet = await localWallet.hasWallet();
            const createSection = document.getElementById('lightWalletCreate');
            const unlockSection = document.getElementById('lightWalletUnlock');
            const unlockedSection = document.getElementById('lightWalletUnlocked');

            if (!hasWallet) {
                // No wallet exists
                createSection.style.display = 'block';
                unlockSection.style.display = 'none';
                unlockedSection.style.display = 'none';
            } else if (!localWallet.isWalletUnlocked()) {
                // Wallet exists but locked.
                const isEncrypted = await localWallet.isWalletEncrypted();
                if (!isEncrypted) {
                    // LP-9: legacy unencrypted (plaintext-at-rest) wallet — do NOT
                    // silently unlock. Present the BLOCKING "secure your wallet" step.
                    createSection.style.display = 'none';
                    unlockSection.style.display = 'none';
                    unlockedSection.style.display = 'none';
                    presentWalletMigration();
                } else {
                    createSection.style.display = 'none';
                    unlockSection.style.display = 'block';
                    unlockedSection.style.display = 'none';
                }
            } else {
                // Wallet unlocked
                createSection.style.display = 'none';
                unlockSection.style.display = 'none';
                unlockedSection.style.display = 'block';
            }
        }

        // Show create wallet modal
        function showCreateLightWallet() {
            document.getElementById('lightWalletModal').style.display = 'flex';
            document.getElementById('createWalletForm').style.display = 'block';
            document.getElementById('restoreWalletForm').style.display = 'none';
            document.getElementById('showMnemonicForm').style.display = 'none';
        }

        // Show restore wallet modal
        function showRestoreLightWallet() {
            document.getElementById('lightWalletModal').style.display = 'flex';
            document.getElementById('createWalletForm').style.display = 'none';
            document.getElementById('restoreWalletForm').style.display = 'block';
            document.getElementById('showMnemonicForm').style.display = 'none';
        }

        // Close modal
        function closeLightWalletModal() {
            document.getElementById('lightWalletModal').style.display = 'none';
            currentMnemonic = null;
        }

        // Create new light wallet
        async function createLightWallet() {
            const password = document.getElementById('newLightPassword').value;
            const confirm = document.getElementById('confirmLightPassword').value;

            if (password.length < 8) {
                showNotification('Password must be at least 8 characters', 'error');
                return;
            }
            if (password !== confirm) {
                showNotification('Passwords do not match', 'error');
                return;
            }

            try {
                showNotification('Creating wallet...', 'info');
                const result = await localWallet.createWallet(password);

                // Store mnemonic temporarily
                currentMnemonic = result.mnemonic;

                // Show mnemonic
                document.getElementById('createWalletForm').style.display = 'none';
                document.getElementById('showMnemonicForm').style.display = 'block';

                // Display mnemonic words
                const display = document.getElementById('lightWalletMnemonicDisplay');
                display.innerHTML = result.mnemonic.map((word, i) =>
                    `<span style="display: inline-block; background: var(--bg-card); padding: 4px 8px; margin: 4px; border-radius: 4px;">${i + 1}. ${word}</span>`
                ).join('');

                showNotification('Wallet created successfully!', 'success');

            } catch (e) {
                showNotification('Failed to create wallet: ' + e.message, 'error');
            }
        }

        // Confirm mnemonic backup
        function confirmMnemonicBackup() {
            currentMnemonic = null;  // Clear from memory
            closeLightWalletModal();
            updateLightWalletUI();
        }

        // Restore light wallet
        async function restoreLightWallet() {
            const mnemonicText = document.getElementById('restoreMnemonic').value.trim();
            const password = document.getElementById('restoreLightPassword').value;

            if (!mnemonicText) {
                showNotification('Please enter your mnemonic phrase', 'error');
                return;
            }

            // LP-9: a password is mandatory — a blank/short password is rejected,
            // never silently coerced to an unencrypted (plaintext-at-rest) wallet.
            if (!password || password.length < 8) {
                showNotification('Password must be at least 8 characters', 'error');
                return;
            }

            const mnemonic = mnemonicText.toLowerCase().split(/\s+/);
            if (mnemonic.length !== 24) {
                showNotification('Mnemonic must be 24 words', 'error');
                return;
            }

            try {
                showNotification('Restoring wallet...', 'info');
                await localWallet.importWallet(password, mnemonic);

                closeLightWalletModal();
                updateLightWalletUI();

                showNotification('Wallet restored and encrypted successfully!', 'success');

            } catch (e) {
                showNotification('Failed to restore wallet: ' + e.message, 'error');
            }
        }

        // LP-9: present the blocking "secure your wallet" migration step for a legacy
        // unencrypted wallet. Idempotent — safe to call from multiple chokepoints.
        function presentWalletMigration() {
            const modal = document.getElementById('walletMigrationModal');
            if (!modal) return;
            // Hide any welcome screen so the migration is the only visible surface.
            const welcome = document.getElementById('page-welcome');
            if (welcome) welcome.style.display = 'none';
            const errEl = document.getElementById('migrationError');
            if (errEl) { errEl.style.display = 'none'; errEl.textContent = ''; }
            modal.style.display = 'flex';
            const pw = document.getElementById('migrationPassword');
            if (pw) pw.focus();
        }

        // LP-9: perform the in-place encryption migration. Hard-blocks until success.
        async function submitWalletMigration() {
            const btn = document.getElementById('migrationSubmitBtn');
            const errEl = document.getElementById('migrationError');
            const showErr = (msg) => {
                if (errEl) { errEl.textContent = msg; errEl.style.display = 'block'; }
            };

            const pw = document.getElementById('migrationPassword').value;
            const pw2 = document.getElementById('migrationPasswordConfirm').value;

            if (!pw || pw.length < 8) { showErr('Password must be at least 8 characters'); return; }
            if (pw !== pw2) { showErr('Passwords do not match'); return; }

            if (btn) { btn.disabled = true; btn.textContent = 'Encrypting…'; }
            try {
                // Race-tolerant: if another tab already encrypted, encryptExisting returns
                // false — fall back to unlocking with the supplied password.
                const migrated = await localWallet.encryptExisting(pw);
                if (!migrated) {
                    // Already encrypted elsewhere; try to unlock with this password.
                    try {
                        await localWallet.unlock(pw);
                    } catch (e) {
                        showErr('This wallet was already secured in another tab. Please reload and enter your password.');
                        if (btn) { btn.disabled = false; btn.textContent = 'Encrypt & Continue'; }
                        return;
                    }
                }

                // Clear the password fields from the DOM.
                document.getElementById('migrationPassword').value = '';
                document.getElementById('migrationPasswordConfirm').value = '';

                // Close the modal and proceed into the wallet.
                document.getElementById('walletMigrationModal').style.display = 'none';
                showNotification('Wallet encrypted successfully. Your addresses are unchanged.', 'success');

                // Show sidebar + dashboard, mirror the welcomeFinish() entry path.
                const welcome = document.getElementById('page-welcome');
                if (welcome) welcome.style.display = 'none';
                document.querySelectorAll('.nav-item').forEach(i => i.style.display = '');
                await updateLightWalletUI();
                navigateTo('dashboard');

                // Establish connection if needed.
                const savedMode = localStorage.getItem('dilithionWalletMode');
                if (savedMode === 'light') {
                    try { await handleModeChange(); } catch (e) { /* connection handled elsewhere */ }
                }
            } catch (e) {
                const msg = (e && e.message) ? e.message : 'unknown error';
                // The "raced" case (another tab encrypted this wallet first) DID change the
                // stored wallet, so the "your wallet is unchanged" reassurance would be wrong.
                // That error message already explains the situation; surface it as-is. Only
                // append "unchanged" for genuine failures where the wallet is truly untouched.
                const raced = /encrypted in another tab/i.test(msg);
                showErr(raced
                    ? ('Could not encrypt wallet: ' + msg)
                    : ('Could not encrypt wallet: ' + msg + ' — your wallet is unchanged. Please try again.'));
                if (btn) { btn.disabled = false; btn.textContent = 'Encrypt & Continue'; }
                return;
            }
            if (btn) { btn.disabled = false; btn.textContent = 'Encrypt & Continue'; }
        }

        // Unlock light wallet
        async function unlockLightWallet() {
            const password = document.getElementById('lightWalletPassword').value;

            if (!password) {
                showNotification('Please enter your password', 'error');
                return;
            }

            try {
                await localWallet.unlock(password);
                document.getElementById('lightWalletPassword').value = '';
                updateLightWalletUI();
                showNotification('Wallet unlocked', 'success');

                // Connect to network
                if (connectionManager) {
                    try {
                        setConnectionStatus(false, 'Connecting...');
                        await connectionManager.connect();
                        setConnectionStatus(true, 'Light Wallet');
                        // Refresh data immediately after connection
                        await refreshAll();
                    } catch (e) {
                        setConnectionStatus(false, 'Connection failed');
                        showNotification('Connected to wallet but failed to reach seed node: ' + e.message, 'warning');
                    }
                }

            } catch (e) {
                if (e && e.message === 'WALLET_NEEDS_ENCRYPTION') {
                    // LP-9: legacy unencrypted wallet — route to the blocking migration.
                    presentWalletMigration();
                    return;
                }
                showNotification('Failed to unlock: ' + e.message, 'error');
            }
        }

        // Lock light wallet
        function lockLightWallet() {
            if (localWallet) {
                localWallet.lock();
                updateLightWalletUI();
                showNotification('Wallet locked', 'success');
            }
        }

        // Show backup mnemonic (placeholder - needs password verification)
        function showBackupMnemonic() {
            showNotification('Your recovery phrase was shown when you created your wallet. For security, it is not stored in the browser. Make sure to keep a backup of your wallet.dat file.', 'info');
        }

        // ============================================================
        // Node Wallet Encryption Functions
        // ============================================================

        // Check node wallet encryption status
        async function checkNodeWalletEncryption() {
            // Only show in full node mode
            const mode = connectionManager ? connectionManager.getMode() : 'full';
            const card = document.getElementById('nodeWalletSecurityCard');

            console.log('[Wallet] checkNodeWalletEncryption - mode:', mode, 'connected:', connected);

            if (mode !== 'full' || !connected) {
                card.style.display = 'none';
                return;
            }

            card.style.display = 'block';

            try {
                // Try to get wallet info to check if encrypted
                const walletInfo = await rpcCall('getwalletinfo');
                console.log('[Wallet] getwalletinfo response:', JSON.stringify(walletInfo));

                // Handle both boolean and string responses
                const isEncrypted = walletInfo.encrypted === true || walletInfo.encrypted === 'true';
                console.log('[Wallet] isEncrypted:', isEncrypted);

                document.getElementById('nodeWalletNotEncrypted').style.display = isEncrypted ? 'none' : 'block';
                document.getElementById('nodeWalletEncrypted').style.display = isEncrypted ? 'block' : 'none';

                if (isEncrypted) {
                    const lockStatus = document.getElementById('nodeWalletLockStatus');
                    const isUnlocked = walletInfo.unlocked_until > 0 || walletInfo.locked === false;
                    lockStatus.textContent = isUnlocked ? 'Unlocked' : 'Locked';
                }
            } catch (e) {
                // If getwalletinfo fails, show error state instead of assuming not encrypted
                console.error('[Wallet] Failed to check encryption status:', e.message);
                document.getElementById('nodeWalletNotEncrypted').style.display = 'block';
                document.getElementById('nodeWalletEncrypted').style.display = 'none';
            }
        }

        // Encrypt node wallet
        async function encryptNodeWallet() {
            const password = document.getElementById('encryptWalletPassword').value;
            const confirmPassword = document.getElementById('encryptWalletPasswordConfirm').value;

            if (!password || password.length < 8) {
                showNotification('Password must be at least 8 characters', 'error');
                return;
            }

            if (password !== confirmPassword) {
                showNotification('Passwords do not match', 'error');
                return;
            }

            try {
                showNotification('Encrypting wallet...', 'info');
                await rpcCall('encryptwallet', {passphrase: password});

                // Clear password fields
                document.getElementById('encryptWalletPassword').value = '';
                document.getElementById('encryptWalletPasswordConfirm').value = '';

                showNotification('Wallet encrypted successfully! The node may restart.', 'success');

                // Refresh encryption status
                setTimeout(() => checkNodeWalletEncryption(), 2000);
            } catch (e) {
                showNotification('Failed to encrypt wallet: ' + e.message, 'error');
            }
        }

        // Encrypt wallet from dashboard banner
        async function encryptFromBanner() {
            const password = document.getElementById('bannerEncryptPw').value;
            const confirmPassword = document.getElementById('bannerEncryptPwConfirm').value;

            if (!password || password.length < 8) {
                showNotification('Password must be at least 8 characters', 'error');
                return;
            }

            if (password !== confirmPassword) {
                showNotification('Passwords do not match', 'error');
                return;
            }

            try {
                showNotification('Encrypting wallet...', 'info');
                await rpcCall('encryptwallet', {passphrase: password});

                // Clear password fields
                document.getElementById('bannerEncryptPw').value = '';
                document.getElementById('bannerEncryptPwConfirm').value = '';

                showNotification('Wallet encrypted successfully! You will need this password to unlock for mining and sending.', 'success');

                // Update banners
                document.getElementById('encryptionWarningBanner').style.display = 'none';
                document.getElementById('encryptionOkBanner').style.display = 'block';

                // Refresh encryption status after node processes the change
                setTimeout(() => {
                    checkNodeWalletEncryption();
                    updateDashboardEncryptionBanner();
                }, 2000);
            } catch (e) {
                showNotification('Failed to encrypt wallet: ' + e.message, 'error');
            }
        }

        // Update dashboard encryption banner based on wallet state
        async function updateDashboardEncryptionBanner() {
            const mode = connectionManager ? connectionManager.getMode() : 'full';
            const warningBanner = document.getElementById('encryptionWarningBanner');
            const okBanner = document.getElementById('encryptionOkBanner');

            // Only show in full node mode when connected
            if (mode !== 'full' || !connected) {
                warningBanner.style.display = 'none';
                okBanner.style.display = 'none';
                return;
            }

            try {
                const walletInfo = await rpcCall('getwalletinfo');
                const isEncrypted = walletInfo.encrypted === true || walletInfo.encrypted === 'true';

                warningBanner.style.display = isEncrypted ? 'none' : 'block';
                okBanner.style.display = isEncrypted ? 'block' : 'none';

                // Auto-hide the "encrypted OK" banner after 10 seconds (not a permanent fixture)
                if (isEncrypted) {
                    setTimeout(() => {
                        okBanner.style.display = 'none';
                    }, 10000);
                }
            } catch (e) {
                // If we can't check, hide both banners
                warningBanner.style.display = 'none';
                okBanner.style.display = 'none';
            }
        }

        // Change node wallet password
        async function changeNodeWalletPassword() {
            const oldPassword = document.getElementById('oldNodePassword').value;
            const newPassword = document.getElementById('newNodePassword').value;
            const confirmPassword = document.getElementById('confirmNewNodePassword').value;

            if (!oldPassword) {
                showNotification('Please enter your current password', 'error');
                return;
            }

            if (!newPassword || newPassword.length < 8) {
                showNotification('New password must be at least 8 characters', 'error');
                return;
            }

            if (newPassword !== confirmPassword) {
                showNotification('New passwords do not match', 'error');
                return;
            }

            try {
                await rpcCall('walletpassphrasechange', {oldpassphrase: oldPassword, newpassphrase: newPassword});

                // Clear password fields
                document.getElementById('oldNodePassword').value = '';
                document.getElementById('newNodePassword').value = '';
                document.getElementById('confirmNewNodePassword').value = '';

                showNotification('Password changed successfully!', 'success');
            } catch (e) {
                showNotification('Failed to change password: ' + e.message, 'error');
            }
        }

        // ============================================================
        // Dashboard Wallet Lock/Unlock Functions
        // ============================================================

        // Track node wallet lock state
        let nodeWalletLocked = true;
        let nodeWalletEncrypted = false;

        // Update dashboard wallet security card
        async function updateDashboardWalletSecurity() {
            const card = document.getElementById('dashboardWalletSecurity');
            const mode = connectionManager ? connectionManager.getMode() : 'full';

            // Only show in full node mode when wallet is encrypted
            if (mode !== 'full' || !connected) {
                card.style.display = 'none';
                return;
            }

            try {
                const walletInfo = await rpcCall('getwalletinfo');
                nodeWalletEncrypted = walletInfo.encrypted === true;
                nodeWalletLocked = walletInfo.locked === true || walletInfo.unlocked_until === 0;

                if (!nodeWalletEncrypted) {
                    card.style.display = 'none';
                    return;
                }

                card.style.display = 'block';

                const icon = document.getElementById('dashWalletLockIcon');
                const status = document.getElementById('dashWalletLockStatus');
                const hint = document.getElementById('dashWalletLockHint');
                const btn = document.getElementById('dashLockBtn');
                const unlockForm = document.getElementById('dashUnlockForm');

                if (nodeWalletLocked) {
                    icon.textContent = '🔒';
                    status.textContent = 'Locked';
                    status.style.color = '#22c55e';
                    hint.textContent = 'Wallet is secure but mining cannot sign blocks';
                    btn.innerHTML = '🔓 Unlock';
                    btn.style.display = 'none';
                    unlockForm.style.display = 'block';
                } else {
                    icon.textContent = '🔓';
                    status.textContent = 'Unlocked';
                    status.style.color = '#f59e0b';
                    hint.textContent = 'Wallet is ready for mining';
                    btn.innerHTML = '🔒 Lock Wallet';
                    btn.style.display = 'block';
                    unlockForm.style.display = 'none';
                }
            } catch (e) {
                console.error('[Wallet] Dashboard security update failed:', e.message);
                card.style.display = 'none';
            }
        }

        // Toggle node wallet lock from dashboard
        async function toggleNodeWalletLock() {
            if (nodeWalletLocked) {
                // Show unlock form
                document.getElementById('dashUnlockForm').style.display = 'block';
                document.getElementById('dashLockBtn').style.display = 'none';
            } else {
                // Lock the wallet
                try {
                    await rpcCall('walletlock');
                    showNotification('Wallet locked. Mining will not be able to sign blocks.', 'warning');
                    await updateDashboardWalletSecurity();
                    await checkNodeWalletEncryption();
                } catch (e) {
                    showNotification('Failed to lock wallet: ' + e.message, 'error');
                }
            }
        }

        // Unlock node wallet from dashboard
        async function unlockNodeWalletFromDash() {
            const password = document.getElementById('dashUnlockPassword').value;

            if (!password) {
                showNotification('Please enter your password', 'error');
                return;
            }

            try {
                // Unlock for a long time (1 year in seconds) for mining
                await rpcCall('walletpassphrase', {passphrase: password, timeout: 31536000});

                document.getElementById('dashUnlockPassword').value = '';
                showNotification('Wallet unlocked. Ready for mining!', 'success');
                await updateDashboardWalletSecurity();
                await checkNodeWalletEncryption();
            } catch (e) {
                showNotification('Failed to unlock: ' + e.message, 'error');
            }
        }

        // Initialize
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', () => {
                navigateTo(item.dataset.page);
            });
        });

        // ========================================================================
        // Welcome Flow (first-time light wallet setup)
        // ========================================================================

        function welcomeCreate() {
            document.getElementById('welcomeCreateFlow').style.display = 'block';
            document.getElementById('welcomeImportFlow').style.display = 'none';
        }

        function welcomeImport() {
            document.getElementById('welcomeImportFlow').style.display = 'block';
            document.getElementById('welcomeCreateFlow').style.display = 'none';
        }

        function welcomeShowUnlock() {
            document.getElementById('welcomeUnlockFlow').style.display = 'block';
            document.getElementById('welcomeCreateFlow').style.display = 'none';
            document.getElementById('welcomeImportFlow').style.display = 'none';
        }

        function welcomeUnlockBack() {
            document.getElementById('welcomeUnlockFlow').style.display = 'none';
        }

        async function welcomeDoUnlock() {
            const pw = document.getElementById('welcomeUnlockPassword').value;
            if (!pw) { showNotification('Enter your password', 'error'); return; }
            try {
                await localWallet.unlock(pw);
                document.getElementById('welcomeUnlockPassword').value = '';
                showNotification('Wallet unlocked', 'success');
                welcomeFinish();
            } catch (e) {
                if (e && e.message === 'WALLET_NEEDS_ENCRYPTION') {
                    presentWalletMigration();
                    return;
                }
                showNotification('Wrong password', 'error');
            }
        }

        function welcomeImportBack() {
            document.getElementById('welcomeImportFlow').style.display = 'none';
        }

        async function welcomeDoCreate() {
            const pw = document.getElementById('welcomeCreatePassword').value;
            const pw2 = document.getElementById('welcomeCreatePasswordConfirm').value;

            if (!pw || pw.length < 8) {
                showNotification('Password must be at least 8 characters', 'error');
                return;
            }
            if (pw !== pw2) {
                showNotification('Passwords do not match', 'error');
                return;
            }

            try {
                const result = await localWallet.createWallet(pw);
                const words = result.mnemonic;
                const wordsArray = Array.isArray(words) ? words : words.split(' ');

                // Display mnemonic
                const container = document.getElementById('welcomeMnemonicWords');
                container.innerHTML = '';
                wordsArray.forEach((word, i) => {
                    const div = document.createElement('div');
                    div.style.cssText = 'background: var(--bg-darker); padding: 8px 10px; border-radius: 6px; border: 1px solid var(--border); font-family: "JetBrains Mono", monospace; font-size: 0.8rem;';
                    div.innerHTML = '<span style="color: var(--text-muted); margin-right: 6px;">' + (i + 1) + '.</span>' + word;
                    container.appendChild(div);
                });

                document.getElementById('welcomeAddress').textContent = result.addresses[0];
                document.getElementById('welcomeCreateFlow').style.display = 'none';
                document.getElementById('welcomeMnemonicDisplay').style.display = 'block';
            } catch (e) {
                showNotification('Failed to create wallet: ' + e.message, 'error');
            }
        }

        async function welcomeDoImport() {
            const mnemonic = document.getElementById('welcomeImportMnemonic').value.trim();
            const pw = document.getElementById('welcomeImportPassword').value;

            if (!pw || pw.length < 8) {
                showNotification('Password must be at least 8 characters', 'error');
                return;
            }

            const words = mnemonic.toLowerCase().split(/\s+/).filter(w => w.length > 0);
            if (words.length !== 24) {
                showNotification('Please enter exactly 24 words. You entered ' + words.length, 'error');
                return;
            }

            try {
                await localWallet.importWallet(pw, words);
                showNotification('Wallet imported! Scanning for addresses...', 'success');
                welcomeFinish();

                // Start HD address scan in background after wallet is loaded
                if (connectionManager && connectionManager.isConnected()) {
                    welcomeStartHDScan();
                } else {
                    // Connect first, then scan
                    try {
                        await handleModeChange();
                        welcomeStartHDScan();
                    } catch (e) {
                        showNotification('Connected but address scan requires API. Try refreshing.', 'warning');
                    }
                }
            } catch (e) {
                showNotification('Import failed: ' + e.message, 'error');
            }
        }

        async function welcomeStartHDScan() {
            const scanStatus = document.getElementById('recentTxList');
            if (scanStatus) {
                scanStatus.innerHTML = '<div style="text-align: center; padding: 20px; color: var(--text-secondary);">' +
                    '<div style="margin-bottom: 8px;">Scanning for addresses...</div>' +
                    '<div id="hdScanProgress" style="font-size: 0.8rem; color: var(--text-muted);">Checking index 1...</div></div>';
            }

            try {
                const result = await localWallet.scanHDAddresses(connectionManager, (index, found) => {
                    const el = document.getElementById('hdScanProgress');
                    if (el) el.textContent = `Checking address ${index} (found ${found} with balance)...`;
                });

                if (scanStatus) {
                    scanStatus.innerHTML = '<div style="text-align: center; padding: 20px; color: var(--success);">' +
                        `Scan complete: found ${result.found} addresses across ${result.scanned} checked.</div>`;
                }
                showNotification(`Scan complete: found ${result.found} additional addresses`, 'success');
                await refreshBalance();
                await refreshTransactions();
            } catch (e) {
                console.warn('[HDScan] Error:', e.message);
                if (scanStatus) {
                    scanStatus.innerHTML = '<div style="text-align: center; padding: 20px; color: var(--text-secondary);">Scan finished.</div>';
                }
                await refreshBalance();
            }
        }

        async function welcomeFinish() {
            document.getElementById('page-welcome').style.display = 'none';
            // Show sidebar nav items
            document.querySelectorAll('.nav-item').forEach(i => i.style.display = '');
            updateLightWalletUI();
            navigateTo('dashboard');

            // Establish connection to seed nodes before loading data
            const savedMode = localStorage.getItem('dilithionWalletMode');
            if (savedMode === 'light') {
                await handleModeChange();
            } else {
                connect();
            }
        }

        // Check if welcome screen should be shown
        // Light mode: show if no browser wallet exists
        // Full mode: show if no node is reachable
        async function checkWelcomeScreen() {
            const isLightMode = localStorage.getItem('dilithionWalletMode') === 'light';

            if (isLightMode) {
                // Light mode: check browser wallet
                if (localWallet) {
                    try {
                        const hasBrowserWallet = await localWallet.hasWallet();
                        if (hasBrowserWallet && localWallet.isWalletUnlocked()) return false;
                        if (hasBrowserWallet) {
                            // LP-9: a legacy UNENCRYPTED wallet must be migrated before
                            // anything else — present the blocking encrypt step instead
                            // of the welcome/unlock screen, and do not show welcome.
                            const isEncrypted = await localWallet.isWalletEncrypted();
                            if (isEncrypted === false) {
                                presentWalletMigration();
                                return false;
                            }
                            // Encrypted wallet, locked — show welcome with unlock option
                            document.getElementById('welcomeUnlockCard').style.display = 'block';
                        }
                    } catch (e) {
                        console.log('[Welcome] Could not check browser wallet:', e.message);
                    }
                }
                // No wallet or wallet is locked → show welcome
            } else {
                // Full mode: check if node is reachable
                try {
                    await rpcCall('getblockchaininfo');
                    return false;  // Node is running, skip welcome
                } catch (e) {
                    // Node not reachable — but don't show welcome in full mode,
                    // just let the normal "Connection failed" flow handle it
                    return false;
                }
            }

            // No wallet — show welcome
            document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
            document.getElementById('page-welcome').style.display = 'block';
            document.getElementById('page-welcome').classList.add('active');
            return true;
        }

        // Check for ?mode=light URL parameter (from website "Web Wallet" link)
        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.get('mode') === 'light') {
            localStorage.setItem('dilithionWalletMode', 'light');
        }

        // Initialize light wallet modules first
        initLightWallet().then(async () => {
            loadSettings();
            initChainSelector();

            // Show welcome screen if no wallet exists
            const showedWelcome = await checkWelcomeScreen();
            if (showedWelcome) return;

            // Auto-connect based on mode
            const savedMode = localStorage.getItem('dilithionWalletMode');
            if (savedMode === 'light') {
                // Light mode: connect to seed nodes
                handleModeChange();
            } else {
                connect();
            }
        });

        // Refit balance text when window resizes (e.g. moving between monitors)
        window.addEventListener('resize', fitBalanceText);

        // Add show/hide toggle to all password fields
        document.querySelectorAll('input[type="password"].form-input').forEach(input => {
            // Skip if already has a toggle (welcome form fields)
            if (input.parentElement.querySelector('span[onclick*="type="]')) return;
            const wrapper = document.createElement('div');
            wrapper.style.position = 'relative';
            input.parentNode.insertBefore(wrapper, input);
            wrapper.appendChild(input);
            input.style.paddingRight = '48px';
            const toggle = document.createElement('span');
            toggle.textContent = 'Show';
            toggle.style.cssText = 'position:absolute;right:12px;top:50%;transform:translateY(-50%);cursor:pointer;font-size:0.75rem;color:var(--text-muted);user-select:none;';
            toggle.onclick = function() {
                input.type = input.type === 'password' ? 'text' : 'password';
                toggle.textContent = input.type === 'password' ? 'Show' : 'Hide';
            };
            wrapper.appendChild(toggle);
        });

        // Register PWA service worker
        if ('serviceWorker' in navigator) {
            navigator.serviceWorker.register('/sw.js').then(reg => {
                console.log('[PWA] Service worker registered');
            }).catch(err => {
                console.log('[PWA] Service worker registration failed:', err.message);
            });
        }

        // BUG #115 FIX: Auto-refresh with serialized requests to prevent connection overload
        let refreshInProgress = false;
        const wait300 = () => new Promise(r => setTimeout(r, 300));

        setInterval(async () => {
            if (connected && !refreshInProgress) {
                refreshInProgress = true;
                try {
                    // Serialize requests with 300ms delays to prevent server socket issues
                    await refreshBalance();
                    await wait300();
                    await refreshBlockchainInfo();
                    await wait300();
                    await refreshTransactions();
                } catch (e) {
                    console.warn('[Wallet] Refresh cycle error:', e.message);
                } finally {
                    refreshInProgress = false;
                }
            }
        }, 10000);  // Refresh every 10 seconds
    </script>
</body>
</html>
)WALLET_HTML";
    return html;
}

#endif // DILITHION_API_WALLET_HTML_H
