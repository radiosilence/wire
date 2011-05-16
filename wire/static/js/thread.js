$(function() {
    $('table.thread td.delmsg a').hide();
    $('table.thread tr').hover(function() {
        $('.delmsg a', this).show();
    }, function() {
        $('.delmsg a', this).hide();
    })
});