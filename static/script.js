function updateBlocklist(ip, port , protocol, action) {
    console.log(arguments.callee.name)
    var body =  JSON.stringify({ ip: ip, port: port, protocol: protocol, action: action })
    fetch('/update_blocklist', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: body
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            console.log('Blocklist updated successfully');
            console.log( body)
        }
    });
}

function toggleBlock(ip, port , protocol, isBlocked, button) {
    console.log(arguments.callee.name)
    const action = isBlocked ? 'unblock' : 'block';
    updateBlocklist(ip, port, protocol, action);
    button.innerText = isBlocked ? 'Block' : 'Unblock';
    button.className = isBlocked ? 'block-btn': 'unblock-btn';
    button.setAttribute('data-blocked', !isBlocked);
}



function listenBlockList(){
    console.log(arguments.callee.name)
    fetch('/get_blocklist')
    .then(response => response.json())
    .then(data => {
        const blocklist = data.blocklist;
        console.log(blocklist)
        const rows = document.querySelectorAll('tbody tr');
        

        rows.forEach(row => {
            const type = row.children[1].innerText;
            const to = row.children[4].innerText;
            const isBlockedCell = row.children[11];
            var ip = to.split(':')[0]; // Extraer IP:puerto
            var port = to.split(':')[1]; // Extraer IP:puerto
            const button = document.createElement('button');
            button.setAttribute('data-ip', ip);
            button.setAttribute('data-port', port);
            button.setAttribute('data-protocol', type);
            var isBlocked = false
            if(blocklist.length === 0){
                button.innerText =  'Block';
                button.className = 'block-btn';
            }
            else{
                // Verificar si esta IP:puerto está en el blocklist
                isBlocked = blocklist.some(item => (item.ip === ip || ip === undefined) &&
                (item.port === port || port === undefined) && 
                item.protocol === type && item.action === 'block');
                button.innerText = isBlocked ?  'Unblock' : 'Block';
                button.className = isBlocked ?  'unblock-btn': 'block-btn';
            }
            button.setAttribute('data-blocked', isBlocked);
            button.onclick = function () {
                const isCurrentlyBlocked = button.getAttribute('data-blocked') === 'true';
                toggleBlock(ip, port, type, isCurrentlyBlocked, button);
            };
            isBlockedCell.appendChild(button);
        });
    });
}

function addContextMenu(){
    const contextMenu = document.getElementById('context-menu');

    document.addEventListener('contextmenu', function(event) {
        event.preventDefault();
        const trigger = event.target.closest('.context-menu-trigger');

        if (trigger) {
            const dataProc = trigger.getAttribute('data-p');
            localStorage.setItem('data-p', dataProc);
            contextMenu.style.display = 'block';
            contextMenu.style.left = `${event.pageX}px`;
            contextMenu.style.top = `${event.pageY}px`;
        } else {
            contextMenu.style.display = 'none';
        }
    });

    document.addEventListener('click', function() {
        contextMenu.style.display = 'none';
    });
}


function updateWatchDog(action){
    console.log("updateWatchDog")

    console.log(arguments.callee.name)
    const dataProc = localStorage.getItem('data-p');
    const body =  JSON.stringify({ action: action, proc: dataProc })
    console.log('body', body)
    fetch('/update_watchdog', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: body
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            console.log('Blocklist updated successfully');
            console.log( body)
        }
        else{
            console.log('Error updating watchDog list')
            console.log( body)
            console.log(data)
        }
    });
}

document.addEventListener('DOMContentLoaded', function() {
    console.log("addEventListener DOMContentLoaded")
    listenBlockList();
    setupSeearchBar();
    addContextMenu();
})

const searchBox = document.getElementById('searchBox');
const searchButton = document.getElementById('searchButton');

function setupSeearchBar()
{
    console.log(arguments.callee.name)
     // Recupera el texto buscado del Local Storage y realiza la búsqueda
     const savedSearch = localStorage.getItem('searchText');
     if (savedSearch) {
		 if(searchBox){
         searchBox.value = savedSearch;
         searchTable(savedSearch);
		 }
     }
}

const summaryButton = document.getElementById('summaryButton');
if (summaryButton){
    summaryButton.addEventListener('click', function() {
        window.open('/get_summary', '_blank');
    })}

const analyticsButton = document.getElementById('analyticsButton');
if (analyticsButton){
    analyticsButton.addEventListener('click', function() {
        window.open('/get_analytics', '_blank');
    })}



// Añade evento al botón de búsqueda
if(searchButton){
searchButton.addEventListener('click', function() {
    console.log("addEventListener click")
    const searchText = searchBox.value.trim();
    searchTable(searchText);
    localStorage.setItem('searchText', searchText);
});
}

// Añade evento para buscar al presionar Enter
if(searchBox){
searchBox.addEventListener('keypress', function(event) {
    console.log("addEventListener keypress")
    if (event.key === 'Enter') {
        const searchText = searchBox.value.trim();
        searchTable(searchText);
        localStorage.setItem('searchText', searchText);
    }
});
}

// Función para buscar en la tabla
function searchTable(text) {
    console.log(arguments.callee.name +": "+ text)
    const rows = document.querySelectorAll('tbody tr');
    if (text === '')
    {
        for (let row of rows) {
            row.style.display = '';
        }
    }
    else{
        for (let row of rows) {
            const cellText = row.textContent.toLowerCase();
            if (cellText.includes(text.toLowerCase())) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        }
    }
}

const links = document.querySelectorAll('a');

// Add click event listener to each link
if(links){
links.forEach(link => {
  link.addEventListener('click', () => {
    // Remove the last-clicked class from all links
    links.forEach(link => link.classList.remove('last-clicked'));

    // Add the last-clicked class to the clicked link
    link.classList.add('last-clicked');
  });
});
}

function copyDomain(domain) {
    navigator.clipboard.writeText(domain).then(() => {
      console.log(`Copied ${domain} to clipboard`);
    }).catch((error) => {
      console.error(`Failed to copy ${domain} to clipboard: ${error}`);
    });
  }

