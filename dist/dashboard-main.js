/*! For license information please see dashboard-main.js.LICENSE.txt */
!function(){"use strict";var n,e={30320:function(n,e,a){var o=a(20144),r=a(16453),i=a(22200),s=a(47450),d=a.n(s),c=a(9980),l=a.n(c),A=a(4820),u=a(79753),p={data:function(){return{isMobile:this._isMobile()}},beforeMount:function(){window.addEventListener("resize",this._onResize)},beforeDestroy:function(){window.removeEventListener("resize",this._onResize)},methods:{_onResize:function(){this.isMobile=this._isMobile()},_isMobile:function(){return document.documentElement.clientWidth<768}}},g=function(t){return(0,u.generateFilePath)("dashboard","","img/")+t},b=function(t){var n=arguments.length>1&&void 0!==arguments[1]?arguments[1]:0,e=arguments.length>2&&void 0!==arguments[2]?arguments[2]:"",a=window.OCA.Theming.enabledThemes,o=-1!==a.join("").indexOf("dark");return"default"===t?e&&"backgroundColor"!==e?(0,u.generateUrl)("/apps/theming/image/background")+"?v="+window.OCA.Theming.cacheBuster:g(o?"eduardo-neves-pedra-azul.jpg":"kamil-porembinski-clouds.jpg"):"custom"===t?(0,u.generateUrl)("/apps/dashboard/background")+"?v="+n:g(t)};function C(t,n,e,a,o,r,i){try{var s=t[r](i),d=s.value}catch(t){return void e(t)}s.done?n(d):Promise.resolve(d).then(a,o)}function h(t){return function(){var n=this,e=arguments;return new Promise((function(a,o){var r=t.apply(n,e);function i(t){C(r,a,o,i,s,"next",t)}function s(t){C(r,a,o,i,s,"throw",t)}i(void 0)}))}}var f=(0,r.loadState)("dashboard","shippedBackgrounds"),v={name:"BackgroundSettings",props:{background:{type:String,default:"default"},themingDefaultBackground:{type:String,default:""}},data:function(){return{backgroundImage:(0,u.generateUrl)("/apps/dashboard/background")+"?v="+Date.now(),loading:!1}},computed:{shippedBackgrounds:function(){return Object.keys(f).map((function(t){return{name:t,url:g(t),preview:g("previews/"+t),details:f[t]}}))}},methods:{update:function(t){var n=this;return h(regeneratorRuntime.mark((function e(){var a,o;return regeneratorRuntime.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:if(a="custom"===t.type||"default"===t.type?t.type:t.value,n.backgroundImage=b(a,t.version,n.themingDefaultBackground),"color"!==t.type&&("default"!==t.type||"backgroundColor"!==n.themingDefaultBackground)){e.next=6;break}return n.$emit("update:background",t),n.loading=!1,e.abrupt("return");case 6:(o=new Image).onload=function(){n.$emit("update:background",t),n.loading=!1},o.src=n.backgroundImage;case 9:case"end":return e.stop()}}),e)})))()},setDefault:function(){var t=this;return h(regeneratorRuntime.mark((function n(){var e;return regeneratorRuntime.wrap((function(n){for(;;)switch(n.prev=n.next){case 0:return t.loading="default",n.next=3,A.default.post((0,u.generateUrl)("/apps/dashboard/background/default"));case 3:e=n.sent,t.update(e.data);case 5:case"end":return n.stop()}}),n)})))()},setShipped:function(t){var n=this;return h(regeneratorRuntime.mark((function e(){var a;return regeneratorRuntime.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return n.loading=t,e.next=3,A.default.post((0,u.generateUrl)("/apps/dashboard/background/shipped"),{value:t});case 3:a=e.sent,n.update(a.data);case 5:case"end":return e.stop()}}),e)})))()},setFile:function(t){var n=this;return h(regeneratorRuntime.mark((function e(){var a;return regeneratorRuntime.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return n.loading="custom",e.next=3,A.default.post((0,u.generateUrl)("/apps/dashboard/background/custom"),{value:t});case 3:a=e.sent,n.update(a.data);case 5:case"end":return e.stop()}}),e)})))()},pickColor:function(){var t=this;return h(regeneratorRuntime.mark((function n(){var e,a;return regeneratorRuntime.wrap((function(n){for(;;)switch(n.prev=n.next){case 0:return t.loading="color",e=OCA&&OCA.Theming?OCA.Theming.color:"#0082c9",n.next=4,A.default.post((0,u.generateUrl)("/apps/dashboard/background/color"),{value:e});case 4:a=n.sent,t.update(a.data);case 6:case"end":return n.stop()}}),n)})))()},pickFile:function(){var n=this;window.OC.dialogs.filepicker(t("dashboard","Insert from {productName}",{productName:OC.theme.name}),(function(t,e){e===OC.dialogs.FILEPICKER_TYPE_CHOOSE&&n.setFile(t)}),!1,["image/png","image/gif","image/jpeg","image/svg"],!0,OC.dialogs.FILEPICKER_TYPE_CHOOSE)}}},m=v,k=a(93379),x=a.n(k),y=a(7795),w=a.n(y),_=a(90569),S=a.n(_),B=a(3565),D=a.n(B),O=a(19216),E=a.n(O),F=a(44589),G=a.n(F),I=a(56510),T={};T.styleTagTransform=G(),T.setAttributes=D(),T.insert=S().bind(null,"head"),T.domAPI=w(),T.insertStyleElement=E(),x()(I.Z,T),I.Z&&I.Z.locals&&I.Z.locals;var j=a(51900),z=(0,j.Z)(m,(function(){var t=this,n=t.$createElement,e=t._self._c||n;return e("div",{staticClass:"background-selector"},[e("button",{staticClass:"background filepicker",class:{active:"custom"===t.background},attrs:{tabindex:"0"},on:{click:t.pickFile}},[t._v("\n\t\t"+t._s(t.t("dashboard","Pick from Files"))+"\n\t")]),t._v(" "),e("button",{staticClass:"background default",class:{"icon-loading":"default"===t.loading,active:"default"===t.background},attrs:{tabindex:"0"},on:{click:t.setDefault}},[t._v("\n\t\t"+t._s(t.t("dashboard","Default images"))+"\n\t")]),t._v(" "),e("button",{staticClass:"background color",class:{active:"custom"===t.background},attrs:{tabindex:"0"},on:{click:t.pickColor}},[t._v("\n\t\t"+t._s(t.t("dashboard","Plain background"))+"\n\t")]),t._v(" "),t._l(t.shippedBackgrounds,(function(n){return e("button",{directives:[{name:"tooltip",rawName:"v-tooltip",value:n.details.attribution,expression:"shippedBackground.details.attribution"}],key:n.name,staticClass:"background",class:{"icon-loading":t.loading===n.name,active:t.background===n.name},style:{"background-image":"url("+n.preview+")"},attrs:{tabindex:"0"},on:{click:function(e){return t.setShipped(n.name)}}})}))],2)}),[],!1,null,"e4c3a7ca",null).exports,R=(0,r.loadState)("dashboard","panels"),P=(0,r.loadState)("dashboard","firstRun"),U=(0,r.loadState)("dashboard","background"),L=(0,r.loadState)("dashboard","themingDefaultBackground"),N=(0,r.loadState)("dashboard","version"),W=(0,r.loadState)("dashboard","shippedBackgrounds"),M={weather:{text:t("dashboard","Weather"),icon:"icon-weather-status"},status:{text:t("dashboard","Status"),icon:"icon-user-status-online"}},q={name:"App",components:{Modal:d(),Draggable:l(),BackgroundSettings:z},mixins:[p],data:function(){var t,n;return{isAdmin:(0,i.getCurrentUser)().isAdmin,timer:new Date,registeredStatus:[],callbacks:{},callbacksStatus:{},allCallbacksStatus:{},statusInfo:M,enabledStatuses:(0,r.loadState)("dashboard","statuses"),panels:R,firstRun:P,displayName:null===(t=(0,i.getCurrentUser)())||void 0===t?void 0:t.displayName,uid:null===(n=(0,i.getCurrentUser)())||void 0===n?void 0:n.uid,layout:(0,r.loadState)("dashboard","layout").filter((function(t){return R[t]})),modal:!1,appStoreUrl:(0,u.generateUrl)("/settings/apps/dashboard"),statuses:{},background:U,themingDefaultBackground:L,version:N}},computed:{backgroundImage:function(){return b(this.background,this.version,this.themingDefaultBackground)},backgroundStyle:function(){return"default"===this.background&&"backgroundColor"===this.themingDefaultBackground||this.background.match(/#[0-9A-Fa-f]{6}/g)?null:{backgroundImage:"url(".concat(this.backgroundImage,")")}},greeting:function(){var n,e=this.timer.getHours();n=e>=22||e<5?"night":e>=18?"evening":e>=12?"afternoon":"morning";var a={morning:{generic:t("dashboard","Good morning"),withName:t("dashboard","Good morning, {name}",{name:this.displayName},void 0,{escape:!1})},afternoon:{generic:t("dashboard","Good afternoon"),withName:t("dashboard","Good afternoon, {name}",{name:this.displayName},void 0,{escape:!1})},evening:{generic:t("dashboard","Good evening"),withName:t("dashboard","Good evening, {name}",{name:this.displayName},void 0,{escape:!1})},night:{generic:t("dashboard","Hello"),withName:t("dashboard","Hello, {name}",{name:this.displayName},void 0,{escape:!1})}};return{text:this.displayName&&this.uid!==this.displayName?a[n].withName:a[n].generic}},isActive:function(){var t=this;return function(n){return t.layout.indexOf(n.id)>-1}},isStatusActive:function(){var t=this;return function(n){return!(n in t.enabledStatuses)||t.enabledStatuses[n]}},sortedAllStatuses:function(){return Object.keys(this.allCallbacksStatus).slice().sort(this.sortStatuses)},sortedPanels:function(){var t=this;return Object.values(this.panels).sort((function(n,e){var a=t.layout.indexOf(n.id),o=t.layout.indexOf(e.id);return-1===a||-1===o?o-a||n.id-e.id:a-o||n.id-e.id}))},sortedRegisteredStatus:function(){return this.registeredStatus.slice().sort(this.sortStatuses)}},watch:{callbacks:function(){this.rerenderPanels()},callbacksStatus:function(){for(var t in this.callbacksStatus){var n=this.$refs["status-"+t];this.statuses[t]&&this.statuses[t].mounted||(n?(this.callbacksStatus[t](n[0]),o.default.set(this.statuses,t,{mounted:!0})):console.error("Failed to register panel in the frontend as no backend data was provided for "+t))}}},mounted:function(){var t=this;this.updateGlobalStyles(),this.updateSkipLink(),window.addEventListener("scroll",this.handleScroll),setInterval((function(){t.timer=new Date}),3e4),this.firstRun&&window.addEventListener("scroll",this.disableFirstrunHint)},destroyed:function(){window.removeEventListener("scroll",this.handleScroll)},methods:{register:function(t,n){o.default.set(this.callbacks,t,n)},registerStatus:function(t,n){var e=this;o.default.set(this.allCallbacksStatus,t,n),this.isStatusActive(t)&&(this.registeredStatus.push(t),this.$nextTick((function(){o.default.set(e.callbacksStatus,t,n)})))},rerenderPanels:function(){for(var t in this.callbacks){var n=this.$refs[t];-1!==this.layout.indexOf(t)&&(this.panels[t]&&this.panels[t].mounted||(n?(this.callbacks[t](n[0],{widget:this.panels[t]}),o.default.set(this.panels[t],"mounted",!0)):console.error("Failed to register panel in the frontend as no backend data was provided for "+t)))}},saveLayout:function(){A.default.post((0,u.generateUrl)("/apps/dashboard/layout"),{layout:this.layout.join(",")})},saveStatuses:function(){A.default.post((0,u.generateUrl)("/apps/dashboard/statuses"),{statuses:JSON.stringify(this.enabledStatuses)})},showModal:function(){this.modal=!0,this.firstRun=!1},closeModal:function(){this.modal=!1},updateCheckbox:function(t,n){var e=this,a=this.layout.indexOf(t.id);!n&&a>-1?this.layout.splice(a,1):this.layout.push(t.id),o.default.set(this.panels[t.id],"mounted",!1),this.saveLayout(),this.$nextTick((function(){return e.rerenderPanels()}))},disableFirstrunHint:function(){var t=this;window.removeEventListener("scroll",this.disableFirstrunHint),setTimeout((function(){t.firstRun=!1}),1e3)},updateBackground:function(t){this.background="custom"===t.type||"default"===t.type?t.type:t.value,this.version=t.version,this.updateGlobalStyles()},updateGlobalStyles:function(){document.body.setAttribute("data-dashboard-background",this.background),window.OCA.Theming.inverted&&document.body.classList.add("dashboard--inverted"),"dark"===(W[this.background]?W[this.background].theming:"light")?document.body.classList.add("dashboard--dark"):document.body.classList.remove("dashboard--dark")},updateSkipLink:function(){document.getElementsByClassName("skip-navigation")[0].setAttribute("href","#app-dashboard")},updateStatusCheckbox:function(t,n){n?this.enableStatus(t):this.disableStatus(t)},enableStatus:function(t){this.enabledStatuses[t]=!0,this.registerStatus(t,this.allCallbacksStatus[t]),this.saveStatuses()},disableStatus:function(t){var n=this;this.enabledStatuses[t]=!1;var e=this.registeredStatus.findIndex((function(n){return n===t}));-1!==e&&(this.registeredStatus.splice(e,1),o.default.set(this.statuses,t,{mounted:!1}),this.$nextTick((function(){o.default.delete(n.callbacksStatus,t)}))),this.saveStatuses()},sortStatuses:function(t,n){var e=t.toLowerCase(),a=n.toLowerCase();return e>a?1:e<a?-1:0},handleScroll:function(){window.scrollY>70?document.body.classList.add("dashboard--scrolled"):document.body.classList.remove("dashboard--scrolled")}}},Z=a(44326),H={};H.styleTagTransform=G(),H.setAttributes=D(),H.insert=S().bind(null,"head"),H.domAPI=w(),H.insertStyleElement=E(),x()(Z.Z,H),Z.Z&&Z.Z.locals&&Z.Z.locals;var Y=(0,j.Z)(q,(function(){var t=this,n=t.$createElement,e=t._self._c||n;return e("div",{style:t.backgroundStyle,attrs:{id:"app-dashboard"}},[e("h2",[t._v(t._s(t.greeting.text))]),t._v(" "),e("ul",{staticClass:"statuses"},t._l(t.sortedRegisteredStatus,(function(t){return e("div",{key:t,attrs:{id:"status-"+t}},[e("div",{ref:"status-"+t,refInFor:!0})])})),0),t._v(" "),e("Draggable",t._b({staticClass:"panels",attrs:{handle:".panel--header"},on:{end:t.saveLayout},model:{value:t.layout,callback:function(n){t.layout=n},expression:"layout"}},"Draggable",{swapThreshold:.3,delay:500,delayOnTouchOnly:!0,touchStartThreshold:3},!1),t._l(t.layout,(function(n){return e("div",{key:t.panels[n].id,staticClass:"panel"},[e("div",{staticClass:"panel--header"},[e("h2",{class:t.panels[n].iconClass},[t._v("\n\t\t\t\t\t"+t._s(t.panels[n].title)+"\n\t\t\t\t")])]),t._v(" "),e("div",{staticClass:"panel--content",class:{loading:!t.panels[n].mounted}},[e("div",{ref:t.panels[n].id,refInFor:!0,attrs:{"data-id":t.panels[n].id}})])])})),0),t._v(" "),e("div",{staticClass:"footer"},[e("a",{staticClass:"edit-panels icon-rename",attrs:{tabindex:"0"},on:{click:t.showModal,keyup:[function(n){return!n.type.indexOf("key")&&t._k(n.keyCode,"enter",13,n.key,"Enter")?null:t.showModal.apply(null,arguments)},function(n){return!n.type.indexOf("key")&&t._k(n.keyCode,"space",32,n.key,[" ","Spacebar"])?null:t.showModal.apply(null,arguments)}]}},[t._v(t._s(t.t("dashboard","Customize")))])]),t._v(" "),t.modal?e("Modal",{attrs:{size:"large"},on:{close:t.closeModal}},[e("div",{staticClass:"modal__content"},[e("h3",[t._v(t._s(t.t("dashboard","Edit widgets")))]),t._v(" "),e("ol",{staticClass:"panels"},t._l(t.sortedAllStatuses,(function(n){return e("li",{key:n},[e("input",{staticClass:"checkbox",attrs:{id:"status-checkbox-"+n,type:"checkbox"},domProps:{checked:t.isStatusActive(n)},on:{input:function(e){return t.updateStatusCheckbox(n,e.target.checked)}}}),t._v(" "),e("label",{class:t.statusInfo[n].icon,attrs:{for:"status-checkbox-"+n}},[t._v("\n\t\t\t\t\t\t"+t._s(t.statusInfo[n].text)+"\n\t\t\t\t\t")])])})),0),t._v(" "),e("Draggable",t._b({staticClass:"panels",attrs:{tag:"ol",handle:".draggable"},on:{end:t.saveLayout},model:{value:t.layout,callback:function(n){t.layout=n},expression:"layout"}},"Draggable",{swapThreshold:.3,delay:500,delayOnTouchOnly:!0,touchStartThreshold:3},!1),t._l(t.sortedPanels,(function(n){return e("li",{key:n.id},[e("input",{staticClass:"checkbox",attrs:{id:"panel-checkbox-"+n.id,type:"checkbox"},domProps:{checked:t.isActive(n)},on:{input:function(e){return t.updateCheckbox(n,e.target.checked)}}}),t._v(" "),e("label",{class:t.isActive(n)?"draggable "+n.iconClass:n.iconClass,attrs:{for:"panel-checkbox-"+n.id}},[t._v("\n\t\t\t\t\t\t"+t._s(n.title)+"\n\t\t\t\t\t")])])})),0),t._v(" "),t.isAdmin?e("a",{staticClass:"button",attrs:{href:t.appStoreUrl}},[t._v(t._s(t.t("dashboard","Get more widgets from the App Store")))]):t._e(),t._v(" "),e("h3",[t._v(t._s(t.t("dashboard","Change background image")))]),t._v(" "),e("BackgroundSettings",{attrs:{background:t.background,"theming-default-background":t.themingDefaultBackground},on:{"update:background":t.updateBackground}}),t._v(" "),e("h3",[t._v(t._s(t.t("dashboard","Weather service")))]),t._v(" "),e("p",[t._v("\n\t\t\t\t"+t._s(t.t("dashboard","For your privacy, the weather data is requested by your Nextcloud server on your behalf so the weather service receives no personal information."))+"\n\t\t\t")]),t._v(" "),e("p",{staticClass:"credits--end"},[e("a",{attrs:{href:"https://api.met.no/doc/TermsOfService",target:"_blank",rel:"noopener"}},[t._v(t._s(t.t("dashboard","Weather data from Met.no")))]),t._v(",\n\t\t\t\t"),e("a",{attrs:{href:"https://wiki.osmfoundation.org/wiki/Privacy_Policy",target:"_blank",rel:"noopener"}},[t._v(t._s(t.t("dashboard","geocoding with Nominatim")))]),t._v(",\n\t\t\t\t"),e("a",{attrs:{href:"https://www.opentopodata.org/#public-api",target:"_blank",rel:"noopener"}},[t._v(t._s(t.t("dashboard","elevation data from OpenTopoData")))]),t._v(".\n\t\t\t")])],1)]):t._e()],1)}),[],!1,null,"af526754",null),$=Y.exports,K=a(9944),Q=a(15168),J=a.n(Q);a.nc=btoa((0,i.getRequestToken)()),o.default.directive("Tooltip",J()),o.default.prototype.t=K.translate,window.OCA.Files||(window.OCA.Files={}),Object.assign(window.OCA.Files,{App:{fileList:{filesClient:OC.Files.getClient()}}},window.OCA.Files);var V=new(o.default.extend($))({}).$mount("#app-content-vue");window.OCA.Dashboard={register:function(t,n){return V.register(t,n)},registerStatus:function(t,n){return V.registerStatus(t,n)}}},44326:function(t,n,e){var a=e(87537),o=e.n(a),r=e(23645),i=e.n(r)()(o());i.push([t.id,"#app-dashboard[data-v-af526754]{width:100%;min-height:100vh;background-size:cover;background-position:center center;background-repeat:no-repeat;background-attachment:fixed;background-color:var(--color-primary);--color-background-translucent: rgba(255, 255, 255, 0.8);--background-blur: blur(10px)}#body-user.theme--dark #app-dashboard[data-v-af526754]{background-color:var(--color-main-background);--color-background-translucent: rgba(24, 24, 24, 0.8)}#body-user.theme--highcontrast #app-dashboard[data-v-af526754]{background-color:var(--color-main-background);--color-background-translucent: var(--color-main-background)}#app-dashboard>h2[data-v-af526754]{color:var(--color-primary-text);text-align:center;font-size:32px;line-height:130%;padding:10vh 16px 0px}.panels[data-v-af526754]{width:auto;margin:auto;max-width:1500px;display:flex;justify-content:center;flex-direction:row;align-items:flex-start;flex-wrap:wrap}.panel[data-v-af526754],.panels>div[data-v-af526754]{width:320px;max-width:100%;margin:16px;background-color:var(--color-background-translucent);-webkit-backdrop-filter:var(--background-blur);backdrop-filter:var(--background-blur);border-radius:var(--border-radius-large)}#body-user.theme--highcontrast .panel[data-v-af526754],#body-user.theme--highcontrast .panels>div[data-v-af526754]{border:2px solid var(--color-border)}.panel.sortable-ghost[data-v-af526754],.panels>div.sortable-ghost[data-v-af526754]{opacity:.1}.panel>.panel--header[data-v-af526754],.panels>div>.panel--header[data-v-af526754]{display:flex;z-index:1;top:50px;padding:16px;cursor:grab}.panel>.panel--header[data-v-af526754],.panel>.panel--header[data-v-af526754]  *,.panels>div>.panel--header[data-v-af526754],.panels>div>.panel--header[data-v-af526754]  *{-webkit-touch-callout:none;-webkit-user-select:none;-khtml-user-select:none;-moz-user-select:none;-ms-user-select:none;user-select:none}.panel>.panel--header[data-v-af526754]:active,.panels>div>.panel--header[data-v-af526754]:active{cursor:grabbing}.panel>.panel--header a[data-v-af526754],.panels>div>.panel--header a[data-v-af526754]{flex-grow:1}.panel>.panel--header>h2[data-v-af526754],.panels>div>.panel--header>h2[data-v-af526754]{display:block;flex-grow:1;margin:0;font-size:20px;line-height:24px;font-weight:bold;background-size:32px;background-position:14px 12px;padding:16px 8px 16px 60px;height:56px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;cursor:grab}.panel>.panel--content[data-v-af526754],.panels>div>.panel--content[data-v-af526754]{margin:0 16px 16px 16px;height:420px;overflow:hidden}@media only screen and (max-width: 709px){.panel>.panel--content[data-v-af526754],.panels>div>.panel--content[data-v-af526754]{height:auto}}.footer[data-v-af526754]{text-align:center;transition:bottom var(--animation-slow) ease-in-out;bottom:0;padding:44px 0}.edit-panels[data-v-af526754]{display:inline-block;margin:auto;background-position:16px center;padding:12px 16px;padding-left:36px;border-radius:var(--border-radius-pill);max-width:200px;opacity:1;text-align:center}.edit-panels[data-v-af526754],.statuses[data-v-af526754]  .action-item .action-item__menutoggle,.statuses[data-v-af526754]  .action-item.action-item--open .action-item__menutoggle{background-color:var(--color-background-translucent);-webkit-backdrop-filter:var(--background-blur);backdrop-filter:var(--background-blur);opacity:1 !important}.edit-panels[data-v-af526754]:hover,.edit-panels[data-v-af526754]:focus,.edit-panels[data-v-af526754]:active,.statuses[data-v-af526754]  .action-item .action-item__menutoggle:hover,.statuses[data-v-af526754]  .action-item .action-item__menutoggle:focus,.statuses[data-v-af526754]  .action-item .action-item__menutoggle:active,.statuses[data-v-af526754]  .action-item.action-item--open .action-item__menutoggle:hover,.statuses[data-v-af526754]  .action-item.action-item--open .action-item__menutoggle:focus,.statuses[data-v-af526754]  .action-item.action-item--open .action-item__menutoggle:active{background-color:var(--color-background-hover) !important}.edit-panels[data-v-af526754]:focus-visible,.statuses[data-v-af526754]  .action-item .action-item__menutoggle:focus-visible,.statuses[data-v-af526754]  .action-item.action-item--open .action-item__menutoggle:focus-visible{border:2px solid var(--color-main-text) !important}.modal__content[data-v-af526754]{padding:32px 16px;text-align:center}.modal__content ol[data-v-af526754]{display:flex;flex-direction:row;justify-content:center;list-style-type:none;padding-bottom:16px}.modal__content li label[data-v-af526754]{position:relative;display:block;padding:48px 16px 14px 16px;margin:8px;width:140px;background-color:var(--color-background-hover);border:2px solid var(--color-main-background);border-radius:var(--border-radius-large);background-size:24px;background-position:16px 16px;text-align:left;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.modal__content li label[data-v-af526754]:hover{border-color:var(--color-primary)}.modal__content li input[type=checkbox].checkbox+label[data-v-af526754]:before{position:absolute;right:12px;top:16px}.modal__content li input:focus+label[data-v-af526754]{border-color:var(--color-primary)}.modal__content h3[data-v-af526754]{font-weight:bold}.modal__content h3[data-v-af526754]:not(:first-of-type){margin-top:64px}.modal__content .button[data-v-af526754]{display:inline-block;padding:10px 16px;margin:0}.modal__content p[data-v-af526754]{max-width:650px;margin:0 auto}.modal__content p a[data-v-af526754]:hover,.modal__content p a[data-v-af526754]:focus{border-bottom:2px solid var(--color-border)}.modal__content .credits--end[data-v-af526754]{padding-bottom:32px;color:var(--color-text-maxcontrast)}.modal__content .credits--end a[data-v-af526754]{color:var(--color-text-maxcontrast)}.flip-list-move[data-v-af526754]{transition:transform var(--animation-slow)}.statuses[data-v-af526754]{display:flex;flex-direction:row;justify-content:center;flex-wrap:wrap;margin-bottom:36px}.statuses>div[data-v-af526754]{margin:8px}","",{version:3,sources:["webpack://./apps/dashboard/src/App.vue"],names:[],mappings:"AAqZA,gCACC,UAAA,CACA,gBAAA,CACA,qBAAA,CACA,iCAAA,CACA,2BAAA,CACA,2BAAA,CACA,qCAAA,CACA,wDAAA,CACA,6BAAA,CAEA,uDACC,6CAAA,CACA,qDAAA,CAGD,+DACC,6CAAA,CACA,4DAAA,CAGD,mCACC,+BAAA,CACA,iBAAA,CACA,cAAA,CACA,gBAAA,CACA,qBAAA,CAIF,yBACC,UAAA,CACA,WAAA,CACA,gBAAA,CACA,YAAA,CACA,sBAAA,CACA,kBAAA,CACA,sBAAA,CACA,cAAA,CAGD,qDACC,WAAA,CACA,cAAA,CACA,WAAA,CACA,oDAAA,CACA,8CAAA,CACA,sCAAA,CACA,wCAAA,CAEA,mHACC,oCAAA,CAGD,mFACE,UAAA,CAGF,mFACC,YAAA,CACA,SAAA,CACA,QAAA,CACA,YAAA,CACA,WAAA,CAEA,4KACC,0BAAA,CACA,wBAAA,CACA,uBAAA,CACA,qBAAA,CACA,oBAAA,CACA,gBAAA,CAGD,iGACC,eAAA,CAGD,uFACC,WAAA,CAGD,yFACC,aAAA,CACA,WAAA,CACA,QAAA,CACA,cAAA,CACA,gBAAA,CACA,gBAAA,CACA,oBAAA,CACA,6BAAA,CACA,0BAAA,CACA,WAAA,CACA,kBAAA,CACA,eAAA,CACA,sBAAA,CACA,WAAA,CAIF,qFACC,uBAAA,CACA,YAAA,CAEA,eAAA,CAID,0CACC,qFACC,WAAA,CAAA,CAKH,yBACC,iBAAA,CACA,mDAAA,CACA,QAAA,CACA,cAAA,CAGD,8BACC,oBAAA,CACA,WAAA,CACA,+BAAA,CACA,iBAAA,CACA,iBAAA,CACA,uCAAA,CACA,eAAA,CACA,SAAA,CACA,iBAAA,CAGD,oLAGC,oDAAA,CACA,8CAAA,CACA,sCAAA,CACA,oBAAA,CAEA,qlBAGC,yDAAA,CAED,8NACC,kDAAA,CAIF,iCACC,iBAAA,CACA,iBAAA,CAEA,oCACC,YAAA,CACA,kBAAA,CACA,sBAAA,CACA,oBAAA,CACA,mBAAA,CAGA,0CACC,iBAAA,CACA,aAAA,CACA,2BAAA,CACA,UAAA,CACA,WAAA,CACA,8CAAA,CACA,6CAAA,CACA,wCAAA,CACA,oBAAA,CACA,6BAAA,CACA,eAAA,CACA,eAAA,CACA,sBAAA,CACA,kBAAA,CAEA,gDACC,iCAAA,CAIF,+EACC,iBAAA,CACA,UAAA,CACA,QAAA,CAGD,sDACC,iCAAA,CAIF,oCACC,gBAAA,CAEA,wDACC,eAAA,CAKF,yCACC,oBAAA,CACA,iBAAA,CACA,QAAA,CAGD,mCACC,eAAA,CACA,aAAA,CAEA,sFAEC,2CAAA,CAIF,+CACC,mBAAA,CACA,mCAAA,CAEA,iDACC,mCAAA,CAKH,iCACC,0CAAA,CAGD,2BACC,YAAA,CACA,kBAAA,CACA,sBAAA,CACA,cAAA,CACA,kBAAA,CAEA,+BACC,UAAA",sourcesContent:["\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n#app-dashboard {\n\twidth: 100%;\n\tmin-height: 100vh;\n\tbackground-size: cover;\n\tbackground-position: center center;\n\tbackground-repeat: no-repeat;\n\tbackground-attachment: fixed;\n\tbackground-color: var(--color-primary);\n\t--color-background-translucent: rgba(255, 255, 255, 0.8);\n\t--background-blur: blur(10px);\n\n\t#body-user.theme--dark & {\n\t\tbackground-color: var(--color-main-background);\n\t\t--color-background-translucent: rgba(24, 24, 24, 0.8);\n\t}\n\n\t#body-user.theme--highcontrast & {\n\t\tbackground-color: var(--color-main-background);\n\t\t--color-background-translucent: var(--color-main-background);\n\t}\n\n\t> h2 {\n\t\tcolor: var(--color-primary-text);\n\t\ttext-align: center;\n\t\tfont-size: 32px;\n\t\tline-height: 130%;\n\t\tpadding: 10vh 16px 0px;\n\t}\n}\n\n.panels {\n\twidth: auto;\n\tmargin: auto;\n\tmax-width: 1500px;\n\tdisplay: flex;\n\tjustify-content: center;\n\tflex-direction: row;\n\talign-items: flex-start;\n\tflex-wrap: wrap;\n}\n\n.panel, .panels > div {\n\twidth: 320px;\n\tmax-width: 100%;\n\tmargin: 16px;\n\tbackground-color: var(--color-background-translucent);\n\t-webkit-backdrop-filter: var(--background-blur);\n\tbackdrop-filter: var(--background-blur);\n\tborder-radius: var(--border-radius-large);\n\n\t#body-user.theme--highcontrast & {\n\t\tborder: 2px solid var(--color-border);\n\t}\n\n\t&.sortable-ghost {\n\t\t opacity: 0.1;\n\t}\n\n\t& > .panel--header {\n\t\tdisplay: flex;\n\t\tz-index: 1;\n\t\ttop: 50px;\n\t\tpadding: 16px;\n\t\tcursor: grab;\n\n\t\t&, ::v-deep * {\n\t\t\t-webkit-touch-callout: none;\n\t\t\t-webkit-user-select: none;\n\t\t\t-khtml-user-select: none;\n\t\t\t-moz-user-select: none;\n\t\t\t-ms-user-select: none;\n\t\t\tuser-select: none;\n\t\t}\n\n\t\t&:active {\n\t\t\tcursor: grabbing;\n\t\t}\n\n\t\ta {\n\t\t\tflex-grow: 1;\n\t\t}\n\n\t\t> h2 {\n\t\t\tdisplay: block;\n\t\t\tflex-grow: 1;\n\t\t\tmargin: 0;\n\t\t\tfont-size: 20px;\n\t\t\tline-height: 24px;\n\t\t\tfont-weight: bold;\n\t\t\tbackground-size: 32px;\n\t\t\tbackground-position: 14px 12px;\n\t\t\tpadding: 16px 8px 16px 60px;\n\t\t\theight: 56px;\n\t\t\twhite-space: nowrap;\n\t\t\toverflow: hidden;\n\t\t\ttext-overflow: ellipsis;\n\t\t\tcursor: grab;\n\t\t}\n\t}\n\n\t& > .panel--content {\n\t\tmargin: 0 16px 16px 16px;\n\t\theight: 420px;\n\t\t// We specifically do not want scrollbars inside widgets\n\t\toverflow: hidden;\n\t}\n\n\t// No need to extend height of widgets if only one column is shown\n\t@media only screen and (max-width: 709px) {\n\t\t& > .panel--content {\n\t\t\theight: auto;\n\t\t}\n\t}\n}\n\n.footer {\n\ttext-align: center;\n\ttransition: bottom var(--animation-slow) ease-in-out;\n\tbottom: 0;\n\tpadding: 44px 0;\n}\n\n.edit-panels {\n\tdisplay: inline-block;\n\tmargin:auto;\n\tbackground-position: 16px center;\n\tpadding: 12px 16px;\n\tpadding-left: 36px;\n\tborder-radius: var(--border-radius-pill);\n\tmax-width: 200px;\n\topacity: 1;\n\ttext-align: center;\n}\n\n.edit-panels,\n.statuses ::v-deep .action-item .action-item__menutoggle,\n.statuses ::v-deep .action-item.action-item--open .action-item__menutoggle {\n\tbackground-color: var(--color-background-translucent);\n\t-webkit-backdrop-filter: var(--background-blur);\n\tbackdrop-filter: var(--background-blur);\n\topacity: 1 !important;\n\n\t&:hover,\n\t&:focus,\n\t&:active {\n\t\tbackground-color: var(--color-background-hover)!important;\n\t}\n\t&:focus-visible {\n\t\tborder: 2px solid var(--color-main-text)!important;\n\t}\n}\n\n.modal__content {\n\tpadding: 32px 16px;\n\ttext-align: center;\n\n\tol {\n\t\tdisplay: flex;\n\t\tflex-direction: row;\n\t\tjustify-content: center;\n\t\tlist-style-type: none;\n\t\tpadding-bottom: 16px;\n\t}\n\tli {\n\t\tlabel {\n\t\t\tposition: relative;\n\t\t\tdisplay: block;\n\t\t\tpadding: 48px 16px 14px 16px;\n\t\t\tmargin: 8px;\n\t\t\twidth: 140px;\n\t\t\tbackground-color: var(--color-background-hover);\n\t\t\tborder: 2px solid var(--color-main-background);\n\t\t\tborder-radius: var(--border-radius-large);\n\t\t\tbackground-size: 24px;\n\t\t\tbackground-position: 16px 16px;\n\t\t\ttext-align: left;\n\t\t\toverflow: hidden;\n\t\t\ttext-overflow: ellipsis;\n\t\t\twhite-space: nowrap;\n\n\t\t\t&:hover {\n\t\t\t\tborder-color: var(--color-primary);\n\t\t\t}\n\t\t}\n\n\t\tinput[type='checkbox'].checkbox + label:before {\n\t\t\tposition: absolute;\n\t\t\tright: 12px;\n\t\t\ttop: 16px;\n\t\t}\n\n\t\tinput:focus + label {\n\t\t\tborder-color: var(--color-primary);\n\t\t}\n\t}\n\n\th3 {\n\t\tfont-weight: bold;\n\n\t\t&:not(:first-of-type) {\n\t\t\tmargin-top: 64px;\n\t\t}\n\t}\n\n\t// Adjust design of 'Get more widgets' button\n\t.button {\n\t\tdisplay: inline-block;\n\t\tpadding: 10px 16px;\n\t\tmargin: 0;\n\t}\n\n\tp {\n\t\tmax-width: 650px;\n\t\tmargin: 0 auto;\n\n\t\ta:hover,\n\t\ta:focus {\n\t\t\tborder-bottom: 2px solid var(--color-border);\n\t\t}\n\t}\n\n\t.credits--end {\n\t\tpadding-bottom: 32px;\n\t\tcolor: var(--color-text-maxcontrast);\n\n\t\ta {\n\t\t\tcolor: var(--color-text-maxcontrast);\n\t\t}\n\t}\n}\n\n.flip-list-move {\n\ttransition: transform var(--animation-slow);\n}\n\n.statuses {\n\tdisplay: flex;\n\tflex-direction: row;\n\tjustify-content: center;\n\tflex-wrap: wrap;\n\tmargin-bottom: 36px;\n\n\t& > div {\n\t\tmargin: 8px;\n\t}\n}\n"],sourceRoot:""}]),n.Z=i},56510:function(t,n,e){var a=e(87537),o=e.n(a),r=e(23645),i=e.n(r)()(o());i.push([t.id,'.background-selector[data-v-e4c3a7ca]{display:flex;flex-wrap:wrap;justify-content:center}.background-selector .background[data-v-e4c3a7ca]{width:176px;height:96px;margin:8px;background-size:cover;background-position:center center;text-align:center;border-radius:var(--border-radius-large);border:2px solid var(--color-main-background);overflow:hidden}.background-selector .background.current[data-v-e4c3a7ca]{background-image:var(--color-background-dark)}.background-selector .background.filepicker[data-v-e4c3a7ca],.background-selector .background.default[data-v-e4c3a7ca],.background-selector .background.color[data-v-e4c3a7ca]{border-color:var(--color-border)}.background-selector .background.color[data-v-e4c3a7ca]{background-color:var(--color-primary);color:var(--color-primary-text)}.background-selector .background.active[data-v-e4c3a7ca],.background-selector .background[data-v-e4c3a7ca]:hover,.background-selector .background[data-v-e4c3a7ca]:focus{border:2px solid var(--color-primary)}.background-selector .background.active[data-v-e4c3a7ca]:not(.icon-loading):after{background-image:var(--icon-checkmark-fff);background-repeat:no-repeat;background-position:center;background-size:44px;content:"";display:block;height:100%}body.theme--dark .background-selector .background.active[data-v-e4c3a7ca]:not(.icon-loading):after{background-image:var(--icon-checkmark-000)}',"",{version:3,sources:["webpack://./apps/dashboard/src/components/BackgroundSettings.vue"],names:[],mappings:"AA4IA,sCACC,YAAA,CACA,cAAA,CACA,sBAAA,CAEA,kDACC,WAAA,CACA,WAAA,CACA,UAAA,CACA,qBAAA,CACA,iCAAA,CACA,iBAAA,CACA,wCAAA,CACA,6CAAA,CACA,eAAA,CAEA,0DACC,6CAAA,CAGD,+KACC,gCAAA,CAGD,wDACC,qCAAA,CACA,+BAAA,CAGD,yKAGC,qCAAA,CAGD,kFACC,0CAAA,CACA,2BAAA,CACA,0BAAA,CACA,oBAAA,CACA,UAAA,CACA,aAAA,CACA,WAAA,CAEA,mGACC,0CAAA",sourcesContent:["\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n.background-selector {\n\tdisplay: flex;\n\tflex-wrap: wrap;\n\tjustify-content: center;\n\n\t.background {\n\t\twidth: 176px;\n\t\theight: 96px;\n\t\tmargin: 8px;\n\t\tbackground-size: cover;\n\t\tbackground-position: center center;\n\t\ttext-align: center;\n\t\tborder-radius: var(--border-radius-large);\n\t\tborder: 2px solid var(--color-main-background);\n\t\toverflow: hidden;\n\n\t\t&.current {\n\t\t\tbackground-image: var(--color-background-dark);\n\t\t}\n\n\t\t&.filepicker, &.default, &.color {\n\t\t\tborder-color: var(--color-border);\n\t\t}\n\n\t\t&.color {\n\t\t\tbackground-color: var(--color-primary);\n\t\t\tcolor: var(--color-primary-text);\n\t\t}\n\n\t\t&.active,\n\t\t&:hover,\n\t\t&:focus {\n\t\t\tborder: 2px solid var(--color-primary);\n\t\t}\n\n\t\t&.active:not(.icon-loading):after {\n\t\t\tbackground-image: var(--icon-checkmark-fff);\n\t\t\tbackground-repeat: no-repeat;\n\t\t\tbackground-position: center;\n\t\t\tbackground-size: 44px;\n\t\t\tcontent: '';\n\t\t\tdisplay: block;\n\t\t\theight: 100%;\n\n\t\t\tbody.theme--dark & {\n\t\t\t\tbackground-image: var(--icon-checkmark-000);\n\t\t\t}\n\t\t}\n\t}\n}\n"],sourceRoot:""}]),n.Z=i}},a={};function o(t){var n=a[t];if(void 0!==n)return n.exports;var r=a[t]={id:t,loaded:!1,exports:{}};return e[t].call(r.exports,r,r.exports,o),r.loaded=!0,r.exports}o.m=e,o.amdD=function(){throw new Error("define cannot be used indirect")},o.amdO={},n=[],o.O=function(t,e,a,r){if(!e){var i=1/0;for(l=0;l<n.length;l++){e=n[l][0],a=n[l][1],r=n[l][2];for(var s=!0,d=0;d<e.length;d++)(!1&r||i>=r)&&Object.keys(o.O).every((function(t){return o.O[t](e[d])}))?e.splice(d--,1):(s=!1,r<i&&(i=r));if(s){n.splice(l--,1);var c=a();void 0!==c&&(t=c)}}return t}r=r||0;for(var l=n.length;l>0&&n[l-1][2]>r;l--)n[l]=n[l-1];n[l]=[e,a,r]},o.n=function(t){var n=t&&t.__esModule?function(){return t.default}:function(){return t};return o.d(n,{a:n}),n},o.d=function(t,n){for(var e in n)o.o(n,e)&&!o.o(t,e)&&Object.defineProperty(t,e,{enumerable:!0,get:n[e]})},o.g=function(){if("object"==typeof globalThis)return globalThis;try{return this||new Function("return this")()}catch(t){if("object"==typeof window)return window}}(),o.o=function(t,n){return Object.prototype.hasOwnProperty.call(t,n)},o.r=function(t){"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(t,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(t,"__esModule",{value:!0})},o.nmd=function(t){return t.paths=[],t.children||(t.children=[]),t},o.j=773,function(){o.b=document.baseURI||self.location.href;var t={773:0};o.O.j=function(n){return 0===t[n]};var n=function(n,e){var a,r,i=e[0],s=e[1],d=e[2],c=0;if(i.some((function(n){return 0!==t[n]}))){for(a in s)o.o(s,a)&&(o.m[a]=s[a]);if(d)var l=d(o)}for(n&&n(e);c<i.length;c++)r=i[c],o.o(t,r)&&t[r]&&t[r][0](),t[r]=0;return o.O(l)},e=self.webpackChunknextcloud=self.webpackChunknextcloud||[];e.forEach(n.bind(null,0)),e.push=n.bind(null,e.push.bind(e))}();var r=o.O(void 0,[874],(function(){return o(30320)}));r=o.O(r)}();
//# sourceMappingURL=dashboard-main.js.map?v=4ea0413619f5fd828d7e