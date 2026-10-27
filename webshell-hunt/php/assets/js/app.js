(function () {
	'use strict';

	// 首页卡片渐入效果。用 IntersectionObserver 避免滚动事件抖动。
	var cards = document.querySelectorAll('.site-main article');
	if (!('IntersectionObserver' in window)) {
		return;
	}

	var io = new IntersectionObserver(function (entries) {
		entries.forEach(function (entry) {
			if (entry.isIntersecting) {
				entry.target.style.opacity = '1';
				entry.target.style.transform = 'none';
				io.unobserve(entry.target);
			}
		});
	}, { threshold: 0.15 });

	cards.forEach(function (card) {
		card.style.opacity = '0';
		card.style.transform = 'translateY(12px)';
		card.style.transition = 'opacity .4s ease, transform .4s ease';
		io.observe(card);
	});
}());
