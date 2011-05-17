$(function() {
    $.getJSON('/async/address-book', function(data) {
        console.log(data);
        $("#recipients").autocomplete(data, {
            multiple: true,
            mustMatch: true,
            autoFill: true
        });        
    });
});