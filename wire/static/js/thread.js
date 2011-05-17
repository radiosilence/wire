$(function() {
    $('article.message header .opts a').hide();
    $('article.message').hover(function() {
        $('header .opts a', this).show();
    }, function() {
        $('header .opts a', this).hide();
    })

    $.getJSON('/async/address-book', function(data) {
        $("#addrecip").autocomplete(data, {
            multiple: true,
            mustMatch: false,
            autoFill: true
        });        
    });
});