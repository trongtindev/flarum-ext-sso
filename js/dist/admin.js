(()=>{var t={n:s=>{var n=s&&s.__esModule?()=>s.default:()=>s;return t.d(n,{a:n}),n},d:(s,n)=>{for(var e in n)t.o(n,e)&&!t.o(s,e)&&Object.defineProperty(s,e,{enumerable:!0,get:n[e]})},o:(t,s)=>Object.prototype.hasOwnProperty.call(t,s),r:t=>{"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(t,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(t,"__esModule",{value:!0})}},s={};(()=>{"use strict";t.r(s);const n=flarum.core.compat["admin/app"];var e=t.n(n);function i(t,s){return i=Object.setPrototypeOf||function(t,s){return t.__proto__=s,t},i(t,s)}const a=flarum.core.compat["admin/components/ExtensionPage"];var o=t.n(a);const l=flarum.core.compat["common/components/Button"];var r=t.n(l),c=function(t){var s,n;function a(){return t.apply(this,arguments)||this}n=t,(s=a).prototype=Object.create(n.prototype),s.prototype.constructor=s,i(s,n);var o=a.prototype;return o.content=function(t){var s=e().extensionData.getSettings(this.extension.id),n=this.flarumClientSettings(1);return m("div",{className:"ExtensionPage-settings"},m("div",{className:"container"},m("div",{className:"Form"},m("div",null,this.buildSettingComponent({type:"checkbox",label:"Provider mode",setting:"maicol07-sso.provider_mode",help:e().translator.trans("maicol07-sso.admin.settings.provider_mode"),className:"maicol07-sso--provider-mode"}),m("div",{hidden:!this.setting("maicol07-sso.provider_mode")()},m("div",{className:"Form-group"},m("table",null,m("thead",null,m("tr",null,n.map((function(t){return m("th",{key:t.setting},t.label,m("br",null),m("span",{className:"helpText",style:{fontWeight:"normal"}},t.help))})))),m("tbody",null,this.clientRows()))),m(r(),{className:"Button","aria-label":"Add instance",icon:"fa fa-plus",onclick:this.addRow.bind(this)},"Add Flarum instance"))),m("hr",null),m("div",{hidden:this.setting("maicol07-sso.provider_mode")()},m("div",{className:"Form-group"},this.generalClientSettings().map(this.buildSettingComponent.bind(this))),null==s?void 0:s.map(this.buildSettingComponent.bind(this)),m("hr",null),m("div",{className:"Form-group"},m("h4",null,e().translator.trans("maicol07-sso.admin.settings.jwt_section_subtitle")),this.jwtSettings().map(this.buildSettingComponent.bind(this)))),m("div",{className:"Form-group"},this.submitButton()))))},o.oncreate=function(s){t.prototype.oncreate.call(this,s),this.setting("maicol07-sso.provider_mode").map((function(){return m.redraw()}))},o.addRow=function(){var t=this.clientRows().length+1;e().data.settings["maicol07-sso.client"+t+"_url"]=""},o.clientRows=function(){for(var t=this,s=[],n=1;"maicol07-sso.client"+n+"_url"in e().data.settings;)s.push(m("tr",{key:"client"+n},this.flarumClientSettings(n).map((function(s){return s.label=void 0,s.help=void 0,m("td",{key:s.setting},t.buildSettingComponent(s))})))),n++;return s},o.flarumClientSettings=function(t){return[{setting:"maicol07-sso.client"+t+"_name",type:"text",label:e().translator.trans("maicol07-sso.admin.settings.client_name"),help:e().translator.trans("maicol07-sso.admin.settings.client_name_help")},{setting:"maicol07-sso.client"+t+"_url",type:"text",label:e().translator.trans("maicol07-sso.admin.settings.client_url"),help:e().translator.trans("maicol07-sso.admin.settings.client_url_help")},{setting:"maicol07-sso.client"+t+"_api_key",type:"password",label:e().translator.trans("maicol07-sso.admin.settings.client_api_key"),help:e().translator.trans("maicol07-sso.admin.settings.client_api_key_help")},{setting:"maicol07-sso.client"+t+"_password_token",type:"password",label:e().translator.trans("maicol07-sso.admin.settings.client_password_token"),help:e().translator.trans("maicol07-sso.admin.settings.client_password_token_help")},{setting:"maicol07-sso.client"+t+"_verify_ssl",type:"checkbox",label:e().translator.trans("maicol07-sso.admin.settings.client_verify_ssl"),help:e().translator.trans("maicol07-sso.admin.settings.client_verify_ssl_help")}]},o.generalClientSettings=function(){return[{setting:"maicol07-sso.login_url",label:e().translator.trans("maicol07-sso.admin.settings.login_url"),type:"url"},{setting:"maicol07-sso.signup_url",label:e().translator.trans("maicol07-sso.admin.settings.signup_url"),type:"url"},{setting:"maicol07-sso.logout_url",label:e().translator.trans("maicol07-sso.admin.settings.logout_url"),type:"url"},{setting:"maicol07-sso.manage_account_url",label:e().translator.trans("maicol07-sso.admin.settings.manage_account_url"),type:"url"},{setting:"maicol07-sso.cookies_prefix",label:e().translator.trans("maicol07-sso.admin.settings.cookies_prefix"),type:"text"}]},o.jwtSettings=function(){return[{setting:"maicol07-sso.jwt_iss",label:e().translator.trans("maicol07-sso.admin.settings.jwt_iss"),type:"text"},{setting:"maicol07-sso.jwt_signing_algorithm",label:e().translator.trans("maicol07-sso.admin.settings.jwt_signing_algorithm"),type:"select",options:{Sha256:"Sha256",Sha384:"Sha384",Sha512:"Sha512"},default:"Sha256"},{setting:"maicol07-sso.jwt_signer_key",label:e().translator.trans("maicol07-sso.admin.settings.jwt_signer_key"),type:"text"}]},a}(o());e().initializers.add("maicol07-sso",(function(){e().extensionData.for("maicol07-sso").registerSetting({setting:"maicol07-sso.manage_account_btn_open_in_new_tab",label:e().translator.trans("maicol07-sso.admin.settings.manage_account_btn_open_in_new_tab"),type:"boolean"}).registerSetting({setting:"maicol07-sso.remove_login_btn",label:e().translator.trans("maicol07-sso.admin.settings.remove_login_btn"),type:"boolean"}).registerSetting({setting:"maicol07-sso.remove_signup_btn",label:e().translator.trans("maicol07-sso.admin.settings.remove_signup_btn"),type:"boolean"}).registerPage(c)}))})(),module.exports=s})();
//# sourceMappingURL=admin.js.map