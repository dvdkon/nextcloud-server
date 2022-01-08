window.addEventListener('DOMContentLoaded', function() {

	OCA.Files_External.Settings.mountConfig.whenSelectAuthMechanism(function($tr, authMechanism, scheme, onCompletion) {
		if (scheme === 'shared_key') {
			var config = $tr.find('.configuration');
			if ($(config).find('[name="public_key_generate"]').length === 0) {
				setupTableRow($tr, config);
				onCompletion.then(function() {
					// If there's no private key, build one
					if (0 === $(config).find('[data-parameter="private_key"]').val().length) {
						generateKeys($tr);
					}
				});
			}
		}
	});

	$('#externalStorage').on('click', '[name="shared_key"]', function(event) {
		event.preventDefault();
		// TODo
	});

	function setupTableRow(tr, config) {
		$(config).append($(document.createElement('input'))
			.addClass('auth-param')
			.attr('type', 'text')
			.attr('value', t('files_external', 'Shared key'))
			.attr('name', 'shared_key')
		);
	}
});
