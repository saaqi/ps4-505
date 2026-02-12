// Offline Cache Status (PS4 5.05 WebKit)
var msgs = document.getElementById("msgs");
if (window.applicationCache) {
  var cache = window.applicationCache;

  cache.ondownloading = function () {
    msgs.innerHTML = "Caching Started!!";
  };

  cache.onprogress = function (e) {
    if (e && e.total) {
      msgs.innerHTML =
        "Caching Status: " +
        Math.round((e.loaded / e.total) * 100) +
        "% Completed";
    } else {
      msgs.innerHTML = "Caching...";
    }
  };

  cache.oncached = function () {
    msgs.innerHTML = "Cached Successfully!!";
    setTimeout(function () {
      msgs.innerHTML = "You can disconnect now.";
    }, 1500);
  };

  cache.onupdateready = function () {
    cache.swapCache();
    msgs.innerHTML = "Cache Updated!";
  };
} else {
  msgs.innerHTML = "Offline cache not supported.";
}
