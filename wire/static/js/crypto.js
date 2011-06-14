$(function() {
    p = {
        iter: 100000,
        mode: "ocb2",
        ks: 256
    };
    rp = {}
    enc_form = '<h1>Security Options</h1> \
    <p><label for="crypto-key">Crypto Key</label><br/> \
        <input type="text" name="encryption_key" id="crypto-key" /> <a href="#" id="encrypt" class="button">Encrypt</a><br/> \
        If you choose to encrypt your message, a key must be decided in person and memorised by the sender and recievers. It must be 8 or more characters long. AVOID dictionary words. \
    </p>';    
    $('article#crypto').html(enc_form);
    $('article#crypto a#encrypt').live('click', function(e) {
        e.preventDefault();
        password = $('#crypto-key').val();
        plaintext = $('#msg-content').val();
        if(password.length < 6) {
            alert('password must be at least x chars');
            return false;
        }
        $('#msg-content').val(sjcl.encrypt(password, plaintext, p));
        $('#msg-encryption').val('aes256');
        $('#msg-content').attr('disabled', 'disabled');
        $('#msg-content').addClass('encrypted_message');
        $('article#crypto').fadeOut('slow', 'swing', function(){
        });
        //$('#msg').append('<div class="ui-state-highlight ui-corner-all response_highlight"><span class="ui-icon ui-icon-info"></span>Message has been encrypted.</div>');
        console.log($('#msg-content').val());
    });
});