$(function() {
    $('table.inbox td.opts a').hide();
    $('table.inbox tr').hover(function() {
        $('.opts a', this).show();
    }, function() {
        $('.opts a', this).hide();
    })
});