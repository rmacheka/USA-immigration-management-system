// DOM Elements
const searchInput = document.querySelector('.search-bar input');
const notificationBell = document.querySelector('.fa-bell');
const notificationContainer = document.querySelector('.notification-container');
const dataTable = document.querySelector('.data-table tbody');

// Notification System
class NotificationSystem {
    constructor() {
        this.notifications = [];
    }

    addNotification(message, type = 'info') {
        const notification = {
            id: Date.now(),
            message,
            type,
            timestamp: new Date()
        };

        this.notifications.unshift(notification);
        this.renderNotifications();
    }

    renderNotifications() {
        notificationContainer.innerHTML = '';
        this.notifications.slice(0, 5).forEach(notification => {
            const notificationElement = document.createElement('div');
            notificationElement.className = `notification ${notification.type}`;
            notificationElement.innerHTML = `
                <p>${notification.message}</p>
                <small>${this.formatTime(notification.timestamp)}</small>
                <button class="close-notification" data-id="${notification.id}">×</button>
            `;
            notificationContainer.appendChild(notificationElement);
        });

        // Update notification badge
        const badge = document.querySelector('.notification-badge');
        badge.textContent = this.notifications.length;
    }

    formatTime(timestamp) {
        const now = new Date();
        const diff = now - timestamp;
        const minutes = Math.floor(diff / 60000);

        if (minutes < 1) return 'Just now';
        if (minutes < 60) return `${minutes}m ago`;
        if (minutes < 1440) return `${Math.floor(minutes / 60)}h ago`;
        return `${Math.floor(minutes / 1440)}d ago`;
    }
}

// Initialize notification system
const notificationSystem = new NotificationSystem();

// Event Listeners
notificationBell.addEventListener('click', () => {
    notificationContainer.classList.toggle('show');
});

// Close notification
notificationContainer.addEventListener('click', (e) => {
    if (e.target.classList.contains('close-notification')) {
        const id = parseInt(e.target.dataset.id);
        notificationSystem.notifications = notificationSystem.notifications.filter(n => n.id !== id);
        notificationSystem.renderNotifications();
    }
});

// Search functionality
searchInput.addEventListener('input', (e) => {
    const searchTerm = e.target.value.toLowerCase();
    const rows = dataTable.querySelectorAll('tr');

    rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(searchTerm) ? '' : 'none';
    });
});

// Table sorting functionality
const sortTable = (columnIndex) => {
    const rows = Array.from(dataTable.querySelectorAll('tr'));
    const header = document.querySelector(`.data-table th:nth-child(${columnIndex + 1})`);
    const isAscending = header.classList.toggle('asc');

    rows.sort((a, b) => {
        const aValue = a.children[columnIndex].textContent;
        const bValue = b.children[columnIndex].textContent;

        if (columnIndex === 0) { // For ID column
            return isAscending ? 
                parseInt(aValue.slice(1)) - parseInt(bValue.slice(1)) :
                parseInt(bValue.slice(1)) - parseInt(aValue.slice(1));
        } else if (columnIndex === 4) { // For Date column
            return isAscending ? 
                new Date(aValue) - new Date(bValue) :
                new Date(bValue) - new Date(aValue);
        } else {
            return isAscending ? 
                aValue.localeCompare(bValue) :
                bValue.localeCompare(aValue);
        }
    });

    dataTable.innerHTML = '';
    rows.forEach(row => dataTable.appendChild(row));
};

// Add sort event listeners to table headers
document.querySelectorAll('.data-table th').forEach((header, index) => {
    header.addEventListener('click', () => sortTable(index));
});

// Sample data for demonstration
const sampleData = [
    {
        id: '#12345',
        name: 'John Doe',
        type: 'Work Visa',
        status: 'pending',
        date: '2024-04-05'
    },
    {
        id: '#12346',
        name: 'Jane Smith',
        type: 'Student Visa',
        status: 'approved',
        date: '2024-04-04'
    },
    {
        id: '#12347',
        name: 'Robert Johnson',
        type: 'Tourist Visa',
        status: 'rejected',
        date: '2024-04-03'
    }
];

// Populate table with sample data
function populateTable() {
    dataTable.innerHTML = '';
    sampleData.forEach(item => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${item.id}</td>
            <td>${item.name}</td>
            <td>${item.type}</td>
            <td><span class="status ${item.status}">${item.status.charAt(0).toUpperCase() + item.status.slice(1)}</span></td>
            <td>${item.date}</td>
            <td>
                <button class="action-btn view"><i class="fas fa-eye"></i></button>
                <button class="action-btn edit"><i class="fas fa-edit"></i></button>
            </td>
        `;
        dataTable.appendChild(row);
    });
}

// Initialize table
populateTable();

// Add some sample notifications
notificationSystem.addNotification('New application received from John Doe', 'info');
notificationSystem.addNotification('Application #12346 has been approved', 'success');
notificationSystem.addNotification('Application #12347 has been rejected', 'error');

// Responsive menu toggle for mobile
const createMobileMenu = () => {
    const menuButton = document.createElement('button');
    menuButton.className = 'mobile-menu-button';
    menuButton.innerHTML = '<i class="fas fa-bars"></i>';
    
    const sidebar = document.querySelector('.sidebar');
    const mainContent = document.querySelector('.main-content');
    
    document.querySelector('.top-bar').prepend(menuButton);
    
    menuButton.addEventListener('click', () => {
        sidebar.classList.toggle('show');
        mainContent.classList.toggle('menu-open');
    });
};

// Initialize mobile menu if screen is small
if (window.innerWidth <= 768) {
    createMobileMenu();
}

// Advanced Search Functionality
class AdvancedSearch {
    constructor() {
        this.searchHistory = [];
        this.currentPage = 1;
        this.resultsPerPage = 10;
        this.initializeSearch();
    }

    initializeSearch() {
        this.setupEventListeners();
        this.loadSearchHistory();
        this.populateCountries();
    }

    setupEventListeners() {
        const searchForm = document.getElementById('advancedSearchForm');
        const clearFiltersBtn = document.getElementById('clearFilters');
        const exportResultsBtn = document.getElementById('exportResults');
        const printResultsBtn = document.getElementById('printResults');

        searchForm.addEventListener('submit', (e) => {
            e.preventDefault();
            this.performSearch();
        });

        clearFiltersBtn.addEventListener('click', () => {
            this.clearFilters();
        });

        exportResultsBtn.addEventListener('click', () => {
            this.exportResults();
        });

        printResultsBtn.addEventListener('click', () => {
            this.printResults();
        });

        // Real-time search suggestions
        const searchInput = document.getElementById('searchQuery');
        searchInput.addEventListener('input', (e) => {
            this.showSearchSuggestions(e.target.value);
        });
    }

    performSearch() {
        const searchParams = this.getSearchParams();
        this.saveToHistory(searchParams);
        this.displayResults(searchParams);
        this.updatePagination();
    }

    getSearchParams() {
        return {
            query: document.getElementById('searchQuery').value,
            applicationTypes: Array.from(document.getElementById('applicationType').selectedOptions).map(opt => opt.value),
            statuses: Array.from(document.getElementById('status').selectedOptions).map(opt => opt.value),
            startDate: document.getElementById('startDate').value,
            endDate: document.getElementById('endDate').value,
            country: document.getElementById('country').value
        };
    }

    saveToHistory(params) {
        this.searchHistory.unshift({
            params,
            timestamp: new Date()
        });
        this.searchHistory = this.searchHistory.slice(0, 5); // Keep only last 5 searches
        this.updateSearchHistory();
        localStorage.setItem('searchHistory', JSON.stringify(this.searchHistory));
    }

    loadSearchHistory() {
        const savedHistory = localStorage.getItem('searchHistory');
        if (savedHistory) {
            this.searchHistory = JSON.parse(savedHistory);
            this.updateSearchHistory();
        }
    }

    updateSearchHistory() {
        const historyList = document.querySelector('.history-list');
        historyList.innerHTML = this.searchHistory.map((search, index) => `
            <div class="history-item" data-index="${index}">
                ${this.formatSearchParams(search.params)}
                <small>${this.formatTime(search.timestamp)}</small>
            </div>
        `).join('');

        // Add click handlers to history items
        document.querySelectorAll('.history-item').forEach(item => {
            item.addEventListener('click', () => {
                const index = item.dataset.index;
                this.loadSearchFromHistory(index);
            });
        });
    }

    formatSearchParams(params) {
        const parts = [];
        if (params.query) parts.push(`Query: ${params.query}`);
        if (params.applicationTypes.length) parts.push(`Types: ${params.applicationTypes.join(', ')}`);
        if (params.statuses.length) parts.push(`Status: ${params.statuses.join(', ')}`);
        if (params.country) parts.push(`Country: ${params.country}`);
        return parts.join(' | ');
    }

    loadSearchFromHistory(index) {
        const search = this.searchHistory[index];
        document.getElementById('searchQuery').value = search.params.query;
        this.setSelectValues('applicationType', search.params.applicationTypes);
        this.setSelectValues('status', search.params.statuses);
        document.getElementById('startDate').value = search.params.startDate;
        document.getElementById('endDate').value = search.params.endDate;
        document.getElementById('country').value = search.params.country;
    }

    setSelectValues(selectId, values) {
        const select = document.getElementById(selectId);
        Array.from(select.options).forEach(option => {
            option.selected = values.includes(option.value);
        });
    }

    clearFilters() {
        document.getElementById('advancedSearchForm').reset();
        this.currentPage = 1;
        this.updatePagination();
    }

    displayResults(params) {
        // This would be replaced with actual API call
        const results = this.getMockResults(params);
        const resultsTable = document.querySelector('.results-table');
        
        resultsTable.innerHTML = `
            <table class="data-table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Name</th>
                        <th>Type</th>
                        <th>Status</th>
                        <th>Date</th>
                        <th>Country</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    ${results.map(result => `
                        <tr>
                            <td>${result.id}</td>
                            <td>${result.name}</td>
                            <td>${result.type}</td>
                            <td><span class="status ${result.status}">${result.status}</span></td>
                            <td>${result.date}</td>
                            <td>${result.country}</td>
                            <td>
                                <button class="action-btn view"><i class="fas fa-eye"></i></button>
                                <button class="action-btn edit"><i class="fas fa-edit"></i></button>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
    }

    getMockResults(params) {
        // Mock data for demonstration
        return [
            {
                id: '#12345',
                name: 'John Doe',
                type: 'Work Visa',
                status: 'pending',
                date: '2024-04-05',
                country: 'Canada'
            },
            {
                id: '#12346',
                name: 'Jane Smith',
                type: 'Student Visa',
                status: 'approved',
                date: '2024-04-04',
                country: 'UK'
            }
        ];
    }

    updatePagination() {
        const pagination = document.querySelector('.pagination');
        const totalPages = Math.ceil(this.getMockResults({}).length / this.resultsPerPage);
        
        let paginationHTML = '';
        for (let i = 1; i <= totalPages; i++) {
            paginationHTML += `
                <button class="${i === this.currentPage ? 'active' : ''}" data-page="${i}">
                    ${i}
                </button>
            `;
        }
        
        pagination.innerHTML = paginationHTML;
        
        // Add click handlers to pagination buttons
        pagination.querySelectorAll('button').forEach(button => {
            button.addEventListener('click', () => {
                this.currentPage = parseInt(button.dataset.page);
                this.performSearch();
            });
        });
    }

    exportResults() {
        // Implement export functionality
        console.log('Exporting results...');
    }

    printResults() {
        window.print();
    }

    showSearchSuggestions(query) {
        if (query.length < 2) return;
        
        // This would be replaced with actual API call
        const suggestions = this.getMockSuggestions(query);
        this.displaySuggestions(suggestions);
    }

    getMockSuggestions(query) {
        return [
            `${query} - Work Visa`,
            `${query} - Student Visa`,
            `${query} - Tourist Visa`
        ];
    }

    displaySuggestions(suggestions) {
        const suggestionsContainer = document.createElement('div');
        suggestionsContainer.className = 'search-suggestions';
        
        suggestions.forEach(suggestion => {
            const div = document.createElement('div');
            div.textContent = suggestion;
            div.addEventListener('click', () => {
                document.getElementById('searchQuery').value = suggestion;
                suggestionsContainer.remove();
            });
            suggestionsContainer.appendChild(div);
        });
        
        const existingSuggestions = document.querySelector('.search-suggestions');
        if (existingSuggestions) {
            existingSuggestions.remove();
        }
        
        document.querySelector('.search-group').appendChild(suggestionsContainer);
    }

    populateCountries() {
        const countrySelect = document.getElementById('country');
        const countries = [
            'United States',
            'Canada',
            'United Kingdom',
            'Australia',
            'Germany',
            'France',
            'Japan',
            'China',
            'India',
            'Brazil'
        ];
        
        countries.forEach(country => {
            const option = document.createElement('option');
            option.value = country;
            option.textContent = country;
            countrySelect.appendChild(option);
        });
    }
}

// Initialize advanced search
const advancedSearch = new AdvancedSearch(); 