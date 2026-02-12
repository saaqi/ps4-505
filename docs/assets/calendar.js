// Show Date Functions ======
function formatAMPM(date) {
  var hours = date.getHours();
  var minutes = date.getMinutes();
  var ampm = hours >= 12 ? "PM" : "AM";
  hours = hours % 12;
  hours = hours ? hours : 12; // the hour '0' should be '12'
  minutes = minutes < 10 ? "0" + minutes : minutes;
  var strTime = hours + ":" + minutes + " " + ampm;
  return strTime;
}
function showdate() {
  var today = new Date();
  var month = ("0" + (today.getMonth() + 1)).slice(-2);
  var day = ("0" + today.getDate()).slice(-2);
  var date = today.getFullYear() + "-" + month + "-" + day;

  document.getElementById("date").innerHTML = date;
  document.getElementById("clock").innerHTML = formatAMPM(today);
}
showdate();
setInterval(showdate, 30000);
