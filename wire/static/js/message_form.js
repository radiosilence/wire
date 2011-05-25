$(function() {
    $.getJSON('/async/address-book', function(data) {
        $("#recipients").autocomplete(data, {
            multiple: true,
            mustMatch: false,
            autoFill: true
        });        
    });
});