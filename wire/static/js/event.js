$(function() {
    $('article.message header .opts a').hide();
    $('article.message').hover(function() {
        $('header .opts a', this).show();
    }, function() {
        $('header .opts a', this).hide();
    })
});