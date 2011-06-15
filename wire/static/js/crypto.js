// Encryption
$(function() {
    window.p = {
        iter: 10000,
        mode: "ocb2",
        ks: 256
    };
});

$(function() {
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
        $('#msg-content').val(sjcl.encrypt(password, plaintext, window.p));
        $('#msg-encryption').val('aes256');

        $('#msg-content').hide();
        $('article#crypto').hide();
        $('#msg').append('<div class="encrypted_message"></div>');
    });
});

// Decryption
$(function() {
    window.encrypted = false;
    $('article.message div.aes256').each(function() {
        window.num_enc = true;
    });
    if(window.num_enc) {
        $('#reply-form').hide();
        //$('#messages').hide();
        $('#decrypt').show();
        $('#decrypt-button').click(function(e) {
            e.preventDefault()
            try {
                $('article.message div.aes256').each(function() {
                    $(this).text(sjcl.decrypt($('#passphrase').val(), $(this).text()));
                    $(this).removeClass('encrypted_message');
                    $('#decrypt').hide();
                });
                $('#decrypt-failed').hide();
                $('#decrypt-success').show();
                $('#messages').show();
                $('#reply-form').show();
            } catch(CORRUPT) {
                $('#decrypt-failed').show();
            }
            
        })
    }
});