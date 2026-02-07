// SETUP MESSAGES ============================
function mouseOutMsg() {
    msgs.innerHTML = 'Saaqi-Host for 5.05';
}


// SETUP HTML PAYLOAD LINKS ============================
function backall() {
    all.style.display = "block";
    backups.style.display = "none";
}

function backuptools() {
    all.style.display = "none"
    backups.style.display = "block";
}

function goldhen23() {
    var link = document.createElement('a');
    document.body.appendChild(link);
    link.href = './payloads/goldhen23.html';
    link.target = 'exp-loader';
    link.click();
}

function goldhenbeta() {
    var link = document.createElement('a');
    document.body.appendChild(link);
    link.href = './payloads/goldhenbeta.html';
    link.target = 'exp-loader';
    link.click();
}

function load_updatesdisable() {
    var link = document.createElement('a');
    document.body.appendChild(link);
    link.href = './payloads/blocker.html';
    link.target = 'exp-loader';
    link.click();
}

function load_updatesenable() {
    var link = document.createElement('a');
    document.body.appendChild(link);
    link.href = './payloads/unblock.html';
    link.target = 'exp-loader';
    link.click();
}

function load_dbBackup() {
    var link = document.createElement('a');
    document.body.appendChild(link);
    link.href = './payloads/db_backup.html';
    link.target = 'exp-loader';
    link.click();
}

function load_dbRestore() {
    var link = document.createElement('a');
    document.body.appendChild(link);
    link.href = './payloads/db_restore.html';
    link.target = 'exp-loader';
    link.click();
}
