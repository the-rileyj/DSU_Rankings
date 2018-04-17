$(document).ready(function () {
    var opponent = document.getElementById("pid");
    var winner = document.getElementById("wpid");
    if(opponent !== undefined) {
        opponent.addEventListener("change", function() {
            if(opponent.selectedIndex) {
                if(winner.length < 3) {
                    var option = document.createElement("option");
                    winner.appendChild(option);
                }

                winner[2].text = opponent[opponent.selectedIndex].text;
                winner[2].value = opponent.value;
            } else {
                if(winner.length > 2)
                    winner.removeChild(winner[winner.length - 1]);
            }
        });
    }
});