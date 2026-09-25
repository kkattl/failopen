# failopen

NetworkPolicy описує сегментацію на рівні Kubernetes, але під ним — реальна
мережа: hostNetwork-поди, NodePort, CNI без enforcement, BGP-анонси podCIDR.
failopen показує розрив між declared (що каже політика) та effective
(що реально дозволяє мережа).

**Статус:** WIP, M0.
