// Populate the sidebar
//
// This is a script, and not included directly in the page, to control the total size of the book.
// The TOC contains an entry for each page, so if each page includes a copy of the TOC,
// the total size of the page becomes O(n**2).
class MDBookSidebarScrollbox extends HTMLElement {
    constructor() {
        super();
    }
    connectedCallback() {
        this.innerHTML = '<ol class="chapter"><li class="chapter-item expanded affix "><a href="ch00-introduction.html">Introduction</a></li><li class="chapter-item expanded "><a href="ch01-api.html"><strong aria-hidden="true">1.</strong> s2n-tls API</a></li><li class="chapter-item expanded "><a href="ch02-initialization.html"><strong aria-hidden="true">2.</strong> Initialization and Teardown</a></li><li class="chapter-item expanded "><a href="ch03-error-handling.html"><strong aria-hidden="true">3.</strong> Error Handling</a></li><li class="chapter-item expanded "><a href="ch04-connection.html"><strong aria-hidden="true">4.</strong> TLS Connections</a></li><li class="chapter-item expanded "><a href="ch05-config.html"><strong aria-hidden="true">5.</strong> Configuring the Connection</a></li><li class="chapter-item expanded "><a href="ch06-security-policies.html"><strong aria-hidden="true">6.</strong> Security Policies</a></li><li class="chapter-item expanded "><a href="ch07-io.html"><strong aria-hidden="true">7.</strong> IO</a></li><li class="chapter-item expanded "><a href="ch08-record-sizes.html"><strong aria-hidden="true">8.</strong> TLS Record Sizes</a></li><li class="chapter-item expanded "><a href="ch09-certificates.html"><strong aria-hidden="true">9.</strong> Certificates and Authentication</a></li><li class="chapter-item expanded "><a href="ch10-client-hello.html"><strong aria-hidden="true">10.</strong> Examining the Client Hello</a></li><li class="chapter-item expanded "><a href="ch11-resumption.html"><strong aria-hidden="true">11.</strong> Session Resumption</a></li><li class="chapter-item expanded "><a href="ch12-private-key-ops.html"><strong aria-hidden="true">12.</strong> Offloading Private Key Operations</a></li><li class="chapter-item expanded "><a href="ch13-preshared-keys.html"><strong aria-hidden="true">13.</strong> Pre-shared Keys</a></li><li class="chapter-item expanded "><a href="ch14-early-data.html"><strong aria-hidden="true">14.</strong> Early Data</a></li><li class="chapter-item expanded "><a href="ch15-post-quantum.html"><strong aria-hidden="true">15.</strong> Post Quantum Support</a></li></ol>';
        // Set the current, active page, and reveal it if it's hidden
        let current_page = document.location.href.toString().split("#")[0];
        if (current_page.endsWith("/")) {
            current_page += "index.html";
        }
        var links = Array.prototype.slice.call(this.querySelectorAll("a"));
        var l = links.length;
        for (var i = 0; i < l; ++i) {
            var link = links[i];
            var href = link.getAttribute("href");
            if (href && !href.startsWith("#") && !/^(?:[a-z+]+:)?\/\//.test(href)) {
                link.href = path_to_root + href;
            }
            // The "index" page is supposed to alias the first chapter in the book.
            if (link.href === current_page || (i === 0 && path_to_root === "" && current_page.endsWith("/index.html"))) {
                link.classList.add("active");
                var parent = link.parentElement;
                if (parent && parent.classList.contains("chapter-item")) {
                    parent.classList.add("expanded");
                }
                while (parent) {
                    if (parent.tagName === "LI" && parent.previousElementSibling) {
                        if (parent.previousElementSibling.classList.contains("chapter-item")) {
                            parent.previousElementSibling.classList.add("expanded");
                        }
                    }
                    parent = parent.parentElement;
                }
            }
        }
        // Track and set sidebar scroll position
        this.addEventListener('click', function(e) {
            if (e.target.tagName === 'A') {
                sessionStorage.setItem('sidebar-scroll', this.scrollTop);
            }
        }, { passive: true });
        var sidebarScrollTop = sessionStorage.getItem('sidebar-scroll');
        sessionStorage.removeItem('sidebar-scroll');
        if (sidebarScrollTop) {
            // preserve sidebar scroll position when navigating via links within sidebar
            this.scrollTop = sidebarScrollTop;
        } else {
            // scroll sidebar to current active section when navigating via "next/previous chapter" buttons
            var activeSection = document.querySelector('#sidebar .active');
            if (activeSection) {
                activeSection.scrollIntoView({ block: 'center' });
            }
        }
        // Toggle buttons
        var sidebarAnchorToggles = document.querySelectorAll('#sidebar a.toggle');
        function toggleSection(ev) {
            ev.currentTarget.parentElement.classList.toggle('expanded');
        }
        Array.from(sidebarAnchorToggles).forEach(function (el) {
            el.addEventListener('click', toggleSection);
        });
    }
}
window.customElements.define("mdbook-sidebar-scrollbox", MDBookSidebarScrollbox);
