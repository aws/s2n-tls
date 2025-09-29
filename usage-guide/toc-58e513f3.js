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
        this.innerHTML = '<ol class="chapter"><li class="chapter-item expanded affix "><a href="ch00-introduction.html">Introduction</a></li><li class="chapter-item expanded "><a href="ch01-api.html"><strong aria-hidden="true">1.</strong> s2n-tls API</a></li><li class="chapter-item expanded "><a href="ch02-initialization.html"><strong aria-hidden="true">2.</strong> Initialization and Teardown</a></li><li class="chapter-item expanded "><a href="ch03-error-handling.html"><strong aria-hidden="true">3.</strong> Error Handling</a></li><li class="chapter-item expanded "><a href="ch04-connection.html"><strong aria-hidden="true">4.</strong> TLS Connections</a></li><li class="chapter-item expanded "><a href="ch05-config.html"><strong aria-hidden="true">5.</strong> Configuring the Connection</a></li><li class="chapter-item expanded "><a href="ch06-security-policies.html"><strong aria-hidden="true">6.</strong> Security Policies</a></li><li class="chapter-item expanded "><a href="ch07-io.html"><strong aria-hidden="true">7.</strong> IO</a></li><li class="chapter-item expanded "><a href="ch08-record-sizes.html"><strong aria-hidden="true">8.</strong> TLS Record Sizes</a></li><li class="chapter-item expanded "><a href="ch09-certificates.html"><strong aria-hidden="true">9.</strong> Certificates and Authentication</a></li><li class="chapter-item expanded "><a href="ch10-client-hello.html"><strong aria-hidden="true">10.</strong> Examining the Client Hello</a></li><li class="chapter-item expanded "><a href="ch11-resumption.html"><strong aria-hidden="true">11.</strong> Session Resumption</a></li><li class="chapter-item expanded "><a href="ch12-preshared-keys.html"><strong aria-hidden="true">12.</strong> Pre-shared Keys</a></li><li class="chapter-item expanded "><a href="ch13-private-key-ops.html"><strong aria-hidden="true">13.</strong> Offloading Private Key Operations</a></li><li class="chapter-item expanded "><a href="ch14-connection-serialization.html"><strong aria-hidden="true">14.</strong> Connection Serialization</a></li><li class="chapter-item expanded "><a href="ch15-early-data.html"><strong aria-hidden="true">15.</strong> Early Data</a></li><li class="chapter-item expanded "><a href="ch16-post-quantum.html"><strong aria-hidden="true">16.</strong> Post Quantum Support</a></li></ol>';
        // Set the current, active page, and reveal it if it's hidden
        let current_page = document.location.href.toString().split('#')[0].split('?')[0];
        if (current_page.endsWith('/')) {
            current_page += 'index.html';
        }
        const links = Array.prototype.slice.call(this.querySelectorAll('a'));
        const l = links.length;
        for (let i = 0; i < l; ++i) {
            const link = links[i];
            const href = link.getAttribute('href');
            if (href && !href.startsWith('#') && !/^(?:[a-z+]+:)?\/\//.test(href)) {
                link.href = path_to_root + href;
            }
            // The 'index' page is supposed to alias the first chapter in the book.
            if (link.href === current_page
                || i === 0
                && path_to_root === ''
                && current_page.endsWith('/index.html')) {
                link.classList.add('active');
                let parent = link.parentElement;
                if (parent && parent.classList.contains('chapter-item')) {
                    parent.classList.add('expanded');
                }
                while (parent) {
                    if (parent.tagName === 'LI' && parent.previousElementSibling) {
                        if (parent.previousElementSibling.classList.contains('chapter-item')) {
                            parent.previousElementSibling.classList.add('expanded');
                        }
                    }
                    parent = parent.parentElement;
                }
            }
        }
        // Track and set sidebar scroll position
        this.addEventListener('click', e => {
            if (e.target.tagName === 'A') {
                sessionStorage.setItem('sidebar-scroll', this.scrollTop);
            }
        }, { passive: true });
        const sidebarScrollTop = sessionStorage.getItem('sidebar-scroll');
        sessionStorage.removeItem('sidebar-scroll');
        if (sidebarScrollTop) {
            // preserve sidebar scroll position when navigating via links within sidebar
            this.scrollTop = sidebarScrollTop;
        } else {
            // scroll sidebar to current active section when navigating via
            // 'next/previous chapter' buttons
            const activeSection = document.querySelector('#mdbook-sidebar .active');
            if (activeSection) {
                activeSection.scrollIntoView({ block: 'center' });
            }
        }
        // Toggle buttons
        const sidebarAnchorToggles = document.querySelectorAll('#mdbook-sidebar a.toggle');
        function toggleSection(ev) {
            ev.currentTarget.parentElement.classList.toggle('expanded');
        }
        Array.from(sidebarAnchorToggles).forEach(el => {
            el.addEventListener('click', toggleSection);
        });
    }
}
window.customElements.define('mdbook-sidebar-scrollbox', MDBookSidebarScrollbox);


// ---------------------------------------------------------------------------
// Support for dynamically adding headers to the sidebar.

// This is a debugging tool for the threshold which you can enable in the console.
// eslint-disable-next-line prefer-const
let mdbookThresholdDebug = false;

(function() {
    // This is used to detect which direction the page has scrolled since the
    // last scroll event.
    let lastKnownScrollPosition = 0;
    // This is the threshold in px from the top of the screen where it will
    // consider a header the "current" header when scrolling down.
    const defaultDownThreshold = 150;
    // Same as defaultDownThreshold, except when scrolling up.
    const defaultUpThreshold = 300;
    // The threshold is a virtual horizontal line on the screen where it
    // considers the "current" header to be above the line. The threshold is
    // modified dynamically to handle headers that are near the bottom of the
    // screen, and to slightly offset the behavior when scrolling up vs down.
    let threshold = defaultDownThreshold;
    // This is used to disable updates while scrolling. This is needed when
    // clicking the header in the sidebar, which triggers a scroll event. It
    // is somewhat finicky to detect when the scroll has finished, so this
    // uses a relatively dumb system of disabling scroll updates for a short
    // time after the click.
    let disableScroll = false;
    // Array of header elements on the page.
    let headers;
    // Array of li elements that are initially collapsed headers in the sidebar.
    // I'm not sure why eslint seems to have a false positive here.
    // eslint-disable-next-line prefer-const
    let headerToggles = [];

    function drawDebugLine() {
        if (!document.body) {
            return;
        }
        const id = 'mdbook-threshold-debug-line';
        const existingLine = document.getElementById(id);
        if (existingLine) {
            existingLine.remove();
        }
        const line = document.createElement('div');
        line.id = id;
        line.style.cssText = `
            position: fixed;
            top: ${threshold}px;
            left: 0;
            width: 100vw;
            height: 2px;
            background-color: red;
            z-index: 9999;
            pointer-events: none;
        `;
        document.body.appendChild(line);
    }

    // Updates the threshold based on the scroll position.
    function updateThreshold() {
        const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
        const windowHeight = window.innerHeight;
        const documentHeight = document.documentElement.scrollHeight;
        // The number of pixels below the viewport, at most documentHeight.
        // This is used to push the threshold down to the bottom of the page
        // as the user scrolls towards the bottom.
        const pixelsBelow = Math.max(0, documentHeight - (scrollTop + windowHeight));
        // The number of pixels above the viewport, at most defaultDownThreshold.
        // Similar to pixelsBelow, this is used to push the threshold back towards
        // the top when reaching the top of the page.
        const pixelsAbove = Math.max(0, defaultDownThreshold - scrollTop);
        // How much the threshold should be offset once it gets close to the
        // bottom of the page.
        let bottomAdd = Math.max(0, windowHeight - pixelsBelow - defaultDownThreshold);

        // Adjusts bottomAdd for a small document. The calculation above
        // assumes the document is at least twice the windowheight in size. If
        // it is less than that, then bottomAdd needs to be shrunk
        // proportional to the difference in size.
        if (documentHeight < windowHeight * 2) {
            const maxPixelsBelow = documentHeight - windowHeight;
            const t = 1 - pixelsBelow / maxPixelsBelow;
            const clamp = Math.max(0, Math.min(1, t));
            bottomAdd *= clamp;
        }

        let scrollingDown = true;
        if (scrollTop < lastKnownScrollPosition) {
            scrollingDown = false;
        }

        if (scrollingDown) {
            // When scrolling down, move the threshold up towards the default
            // downwards threshold position. If near the bottom of the page,
            // bottomAdd will offset the threshold towards the bottom of the
            // page.
            const amountScrolledDown = scrollTop - lastKnownScrollPosition;
            const adjustedDefault = defaultDownThreshold + bottomAdd;
            threshold = Math.max(adjustedDefault, threshold - amountScrolledDown);
        } else {
            // When scrolling up, move the threshold down towards the default
            // upwards threshold position. If near the bottom of the page,
            // quickly transition the threshold back up where it normally
            // belongs.
            const amountScrolledUp = lastKnownScrollPosition - scrollTop;
            const adjustedDefault = defaultUpThreshold - pixelsAbove
                + Math.max(0, bottomAdd - defaultDownThreshold);
            threshold = Math.min(adjustedDefault, threshold + amountScrolledUp);
        }
        lastKnownScrollPosition = scrollTop;
    }

    // Updates which headers in the sidebar should be expanded. If the current
    // header is inside a collapsed group, then it, and all its parents should
    // be expanded.
    function updateHeaderExpanded(currentA) {
        // Add expanded to all header-item li ancestors.
        let current = currentA.parentElement.parentElement.parentElement;
        while (current.tagName === 'LI') {
            const prevSibling = current.previousElementSibling;
            if (prevSibling !== null
                && prevSibling.tagName === 'LI'
                && prevSibling.classList.contains('header-item')) {
                prevSibling.classList.add('expanded');
                current = prevSibling.parentElement.parentElement;
            } else {
                break;
            }
        }
    }

    // Updates which header is marked as the "current" header in the sidebar.
    // This is done with a virtual Y threshold, where headers at or below
    // that line will be considered the current one.
    function updateCurrentHeader() {
        if (mdbookThresholdDebug) {
            drawDebugLine();
        }
        if (!headers || !headers.length) {
            return;
        }

        // Reset the classes, which will be rebuilt below.
        const els = document.getElementsByClassName('current-header');
        for (const el of els) {
            el.classList.remove('current-header');
        }
        for (const toggle of headerToggles) {
            toggle.classList.remove('expanded');
        }

        // Find the last header that is above the threshold.
        let lastHeader = null;
        for (const header of headers) {
            const rect = header.getBoundingClientRect();
            if (rect.top <= threshold) {
                lastHeader = header;
            } else {
                break;
            }
        }
        if (lastHeader === null) {
            lastHeader = headers[0];
            const rect = lastHeader.getBoundingClientRect();
            const windowHeight = window.innerHeight;
            if (rect.top >= windowHeight) {
                return;
            }
        }

        // Get the anchor in the summary.
        const href = '#' + lastHeader.id;
        const a = [...document.querySelectorAll('.header-in-summary')]
            .find(element => element.getAttribute('href') === href);
        if (!a) {
            return;
        }

        a.classList.add('current-header');

        updateHeaderExpanded(a);
    }

    // Updates which header is "current" based on the threshold line.
    function reloadCurrentHeader() {
        if (disableScroll) {
            return;
        }
        updateThreshold();
        updateCurrentHeader();
    }


    // When clicking on a header in the sidebar, this adjusts the threshold so
    // that it is located next to the header. This is so that header becomes
    // "current".
    function headerThresholdClick(event) {
        // See disableScroll description why this is done.
        disableScroll = true;
        setTimeout(() => {
            disableScroll = false;
        }, 100);
        // requestAnimationFrame is used to delay the update of the "current"
        // header until after the scroll is done, and the header is in the new
        // position.
        requestAnimationFrame(() => {
            requestAnimationFrame(() => {
                // Closest is needed because if it has child elements like <code>.
                const a = event.target.closest('a');
                const href = a.getAttribute('href');
                const targetId = href.substring(1);
                const targetElement = document.getElementById(targetId);
                if (targetElement) {
                    threshold = targetElement.getBoundingClientRect().bottom;
                    updateCurrentHeader();
                }
            });
        });
    }

    // Scans page for headers and adds them to the sidebar.
    document.addEventListener('DOMContentLoaded', function() {
        const activeSection = document.querySelector('#mdbook-sidebar .active');
        if (activeSection === null) {
            return;
        }
        const activeItem = activeSection.parentElement;
        const activeList = activeItem.parentElement;

        // Build a tree of headers in the sidebar.
        const rootLi = document.createElement('li');
        rootLi.classList.add('header-item');
        rootLi.classList.add('expanded');
        const rootOl = document.createElement('ol');
        rootOl.classList.add('section');
        rootLi.appendChild(rootOl);
        const stack = [{ level: 0, ol: rootOl }];
        // The level where it will start folding deeply nested headers.
        const foldLevel = 3;

        const main = document.getElementsByTagName('main')[0];
        headers = Array.from(main.querySelectorAll('h2, h3, h4, h5, h6'))
            .filter(h => h.id !== '' && h.children.length && h.children[0].tagName === 'A');

        if (headers.length === 0) {
            return;
        }

        for (let i = 0; i < headers.length; i++) {
            const header = headers[i];
            const level = parseInt(header.tagName.charAt(1));
            const li = document.createElement('li');
            li.classList.add('header-item');
            li.classList.add('expanded');
            if (level < foldLevel) {
                li.classList.add('expanded');
            }
            const a = document.createElement('a');
            a.href = '#' + header.id;
            a.classList.add('header-in-summary');
            a.innerHTML = header.children[0].innerHTML;
            a.addEventListener('click', headerThresholdClick);
            li.appendChild(a);
            const nextHeader = headers[i + 1];
            if (nextHeader !== undefined) {
                const nextLevel = parseInt(nextHeader.tagName.charAt(1));
                if (nextLevel > level && level >= foldLevel) {
                    const div = document.createElement('div');
                    div.textContent = '❱';
                    const toggle = document.createElement('a');
                    toggle.classList.add('toggle');
                    toggle.classList.add('header-toggle');
                    toggle.appendChild(div);
                    toggle.addEventListener('click', () => {
                        li.classList.toggle('expanded');
                    });
                    li.appendChild(toggle);
                    headerToggles.push(li);
                }
            }

            // Find the appropriate parent level.
            while (stack.length > 1 && stack[stack.length - 1].level >= level) {
                stack.pop();
            }

            const currentParent = stack[stack.length - 1];
            currentParent.ol.appendChild(li);

            // Create new nested ol for potential children.
            const nestedOl = document.createElement('ol');
            nestedOl.classList.add('section');
            const nestedLi = document.createElement('li');
            nestedLi.appendChild(nestedOl);
            currentParent.ol.appendChild(nestedLi);
            stack.push({ level: level, ol: nestedOl });
        }

        activeList.insertBefore(rootLi, activeItem.nextSibling);
    });

    document.addEventListener('DOMContentLoaded', reloadCurrentHeader);
    document.addEventListener('scroll', reloadCurrentHeader, { passive: true });
})();

