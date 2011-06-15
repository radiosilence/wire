// Encryption
$(function() {
    window.p = {
        iter: 10000,
        mode: "ocb2",
        ks: 256
    };
});

$(function() {
    $('article#crypto').show();
    $('article#crypto a#encrypt').live('click', function(e) {
        e.preventDefault();
        passphrase = $('#crypto-key').val();
        plaintext = $('#msg-content').val();
        if(passphrase.length < 12) {
            $('#encrypt-failed').show();
            return false;
        }
        $('#msg-content').val(sjcl.encrypt(passphrase, plaintext, window.p));
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
        $('#messages').hide();
        $('#decrypt').show();
        $('#decrypt-button').click(function(e) {
            e.preventDefault()
            try {
                converter = new Showdown.converter();
                $('article.message div.aes256').each(function() {
                    text = sjcl.decrypt($('#passphrase').val(), $(this).text());
                    $(this).html(converter.makeHtml(text));
                    $(this).removeClass('encrypted_message');
                    $(this).removeClass('aes256');
                    $(this).addClass('plain');
                });
                $('#decrypt').hide();
                $('#decrypt-failed').hide();
                $('#decrypt-success').show();
                $('#messages').show();
                $('#reply-form').show();
                window.passphrase = $('#passphrase').val();
            } catch(CORRUPT) {
                $('#decrypt-failed').show();
                $('#decrypt').show();
            }
            
        });

        $('#reply-form').submit(function(e) {
            $('#msg-content').hide()
            $('#msg-content').val(sjcl.encrypt(window.passphrase, $('#msg-content').val(), window.p));
        });
    }
});