function showPassword() {
    var x = document.getElementById('password');
    if (x.type === "password") {
        x.type = "text";
    } else {
        x.type = "password";
    }
}

function showPasswords() {
    var x = document.getElementById('password')
    var y = document.getElementById('password_confirm')
    if (x.type === "password") {
        x.type = "text";
    } else {
        x.type = "password";
    }
    if (y.type === "password") {
        y.type = "text";
    } else {
        y.type = "password";
    }
}