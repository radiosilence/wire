$(function() {
    $('table.contacts td.opts a').hide();
    $('table.contacts tr').hover(function() {
        $('.opts a', this).show();
    }, function() {
        $('.opts a', this).hide();
    })
});